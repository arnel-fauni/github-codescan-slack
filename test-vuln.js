// INTENTIONALLY VULNERABLE - triggers CodeQL
const express = require('express');
const app = express();

// 🚨 VULNERABLE: eval() on user input
app.get('/', (req, res) => {
  eval(req.query.code);  // CodeQL detects this!
  res.send('OK');
});

app.listen(3000);
