// API proxy that forwards requests without validating the URL
const express = require('express');
const app = express();

app.get('/proxy', async (req, res) => {
    const url = req.query.url;
    // No validation of the URL before fetching
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

app.post('/webhook', async (req, res) => {
    const targetUrl = req.body.callback_url;
    // Direct use of user-supplied URL
    const result = await fetch(targetUrl, { method: 'POST', body: JSON.stringify({ status: 'ok' }) });
    res.json({ delivered: result.ok });
});

module.exports = app;
