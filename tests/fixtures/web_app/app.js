/**
 * Sample Web Application - Express server
 * This IS a web application that serves HTML to browsers
 * XSS findings in DOM manipulation should be TRUE POSITIVES
 */

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Serve static HTML page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Test Web App</title></head>
    <body>
      <h1>Test Web Application</h1>
      <div id="output"></div>
      <div id="user-content"></div>
      <script src="/client.js"></script>
    </body>
    </html>
  `);
});

// API endpoint with XSS vulnerability
app.get('/api/message/:msg', (req, res) => {
  const message = req.params.msg;

  // TRUE POSITIVE: This HTML is rendered in browser - XSS risk
  res.send(`
    <!DOCTYPE html>
    <html>
    <body>
      <h1>Message</h1>
      <div>${message}</div>
    </body>
    </html>
  `);
});

// API endpoint returning JSON (not XSS vulnerable)
app.get('/api/data/:id', (req, res) => {
  const userId = req.params.id;
  // This is JSON API - console.log here is server-side logging, not XSS
  console.log(`Fetching data for user: ${userId}`);
  res.json({ id: userId, data: 'sample' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
