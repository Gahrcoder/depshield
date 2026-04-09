// Server that renders HTML with unsanitized user input
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    const title = req.query.title;
    const body = req.query.content;
    // Template literal HTML with unescaped interpolation
    const html = `<html><head><title>${title}</title></head><body>${body}</body></html>`;
    res.send(html);
});

app.get('/profile', (req, res) => {
    const username = req.params.name;
    // String concatenation into HTML
    const card = '<div class="profile">' + username + '</div>';
    res.send(card);
});

app.get('/widget', (req, res) => {
    const config = req.query.config;
    // dangerouslySetInnerHTML in server-rendered React
    const component = `<div dangerouslySetInnerHTML={{ __html: ${config} }} />`;
    res.send(component);
});

module.exports = app;
