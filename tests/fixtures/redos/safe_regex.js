// Module using only static, safe regex patterns

// Simple literal patterns - no user input, no nested quantifiers
const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function isValidEmail(email) {
    return EMAIL_RE.test(email);
}

function isValidUUID(id) {
    return UUID_RE.test(id);
}

function isValidSlug(slug) {
    return SLUG_RE.test(slug);
}

// Dynamic regex but with proper escaping
const _ = require('lodash');
function findExact(items, searchTerm) {
    const escaped = _.escapeRegExp(searchTerm);
    const pattern = new RegExp(escaped, 'i');
    return items.filter(item => pattern.test(item));
}

module.exports = { isValidEmail, isValidUUID, isValidSlug, findExact };
