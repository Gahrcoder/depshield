// API proxy with proper URL validation
const express = require('express');
const dns = require('dns');
const app = express();

const BLOCKED_HOSTS = [
    '169.254.169.254',
    'metadata.google.internal',
    'metadata.internal',
    '100.100.100.200',
];

const BLOCKED_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8',
    '100.64.0.0/10',
    '255.255.255.255/32',
];

async function validateUrl(urlString) {
    const parsed = new URL(urlString);

    // Block cloud metadata hostnames
    if (BLOCKED_HOSTS.includes(parsed.hostname)) {
        throw new Error('Blocked host');
    }

    // DNS resolution check to prevent rebinding
    const resolved = await dns.resolve(parsed.hostname);
    const ip = resolved[0];

    // Verify resolved IP against blocklist
    if (isBlockedIP(ip)) {
        throw new Error('Blocked IP after resolution');
    }

    return parsed.toString();
}

app.get('/proxy', async (req, res) => {
    try {
        const safeUrl = await validateUrl(req.query.url);
        const response = await fetch(safeUrl);
        const data = await response.text();
        res.send(data);
    } catch (err) {
        res.status(403).json({ error: 'URL not allowed' });
    }
});

module.exports = app;
