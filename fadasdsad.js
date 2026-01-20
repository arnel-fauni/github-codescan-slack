// test-secrets.js - GHAS Secret Scanning Test File
// Commit this to verify custom/predefined pattern detection

// Sample AWS Access Key ID and Secret Access Key (triggers AWS patterns)
const awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
const awsSecretAccessKey = 'wJalrXUtnFEMI/K7MDENwerwerG/bPxRfiCYEXAMPLEKEY';
const awsAccessKeyId = 'AKIAIOSFODNasdasdN7EXAMPLE';

// Sample GitHub Personal Access Token (ghp prefix)
const githubToken = 'ghp_1234567890abcdef1234567890abcdef123456';

// Sample generic API token (Base64-like)
const apiToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// Sample weak passwords in config object
const config = {
  databasePassword: 'password123',
  adminPassword: 'letmein',
  secretKey: 'qwertyuiop'
};

// Sample JWT token
const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.example_jwt_signature_here';

// Console log for testing (remove before production)
console.log('Test secrets loaded:', { awsAccessKeyId, githubToken });
