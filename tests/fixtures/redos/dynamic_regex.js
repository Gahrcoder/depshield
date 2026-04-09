// Search handler that builds regex from user input
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    // Dynamic regex from user input without escaping
    const pattern = new RegExp(query, 'gi');
    const results = database.filter(item => pattern.test(item.name));
    res.json(results);
});

app.get('/filter', (req, res) => {
    const filter = req.query.pattern;
    // Template literal regex
    const regex = new RegExp(`^${filter}$`, 'i');
    const matches = items.filter(i => regex.test(i));
    res.json(matches);
});

// Vulnerable regex patterns
const EMAIL_RE = /(([a-zA-Z0-9]+)+)@example.com/;
const PATH_RE = /(\/[a-z]+)+$/;

module.exports = app;
