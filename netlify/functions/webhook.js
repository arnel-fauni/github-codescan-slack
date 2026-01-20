const crypto = require('crypto');

exports.handler = async (event) => {
  // Only accept POST requests
  if (event.httpMethod !== 'POST') {
    return { 
      statusCode: 405, 
      body: JSON.stringify({ error: 'Method Not Allowed' }) 
    };
  }

  // Verify GitHub webhook signature
  const signature = event.headers['x-hub-signature-256'];
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!signature || !webhookSecret) {
    return { statusCode: 401, body: 'Unauthorized' };
  }

  const hmac = crypto.createHmac('sha256', webhookSecret);
  const digest = 'sha256=' + hmac.update(event.body).digest('hex');
  
  if (signature !== digest) {
    return { statusCode: 401, body: 'Signature mismatch' };
  }

  try {
    const payload = JSON.parse(event.body);
    
    // Only process code scanning alert events
    if (payload.action && payload.alert) {
      const alert = payload.alert;
      const severityEmoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
      }[alert.severity] || '⚪';

      const slackMessage = {
        text: `${severityEmoji} *New Code Scanning Alert*`,
        attachments: [{
          color: alert.severity === 'critical' ? 'danger' : 
                  alert.severity === 'high' ? 'warning' : 'good',
          fields: [
            { title: 'Repository', value: payload.repository.full_name, short: true },
            { title: 'Severity', value: `${severityEmoji} ${alert.severity.toUpperCase()}`, short: true },
            { title: 'Rule', value: alert.most_recent_instance.rule.description || 'N/A', short: false },
            { title: 'File', value: `\`${alert.most_recent_instance.location.path}\``, short: true },
            { title: 'Line', value: alert.most_recent_instance.location.start_line.toString(), short: true }
          ],
          actions: [{
            type: 'button',
            text: 'View Alert',
            url: alert.html_url,
            style: 'primary'
          }],
          footer: 'GitHub Advanced Security',
          ts: Date.now() / 1000
        }]
      };

      // Send to Slack webhook or Workflow Builder
      const slackResponse = await fetch(process.env.SLACK_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackMessage)
      });

      if (!slackResponse.ok) {
        console.error('Slack send failed:', await slackResponse.text());
      }
    }

    return { statusCode: 200, body: 'OK' };
  } catch (error) {
    console.error('Error processing webhook:', error);
    return { statusCode: 500, body: 'Internal Server Error' };
  }
};
