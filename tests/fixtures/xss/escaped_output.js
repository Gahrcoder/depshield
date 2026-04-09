// Server that properly escapes all HTML output
const express = require('express');
const DOMPurify = require('dompurify');
const app = express();

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

app.get('/page', (req, res) => {
    const title = escapeHtml(req.query.title);
    const body = DOMPurify.sanitize(req.query.content);
    const html = `<html><head><title>${title}</title></head><body>${body}</body></html>`;
    res.send(html);
});

app.get('/safe', (req, res) => {
    // Using textContent instead of innerHTML
    res.send('<script>document.getElementById("name").textContent = data;</script>');
});

module.exports = app;
