// This file should NOT be flagged by the eval detector

// eval mentioned in a comment - not actual usage
// We used to call eval() here but removed it for security

const config = {
    // eval is disabled in this environment
    evalDisabled: true,
    description: "eval() is not used anywhere in this module",
};

// String containing 'eval' - not an actual call
const WARNING_MSG = "Do not use eval() in production code";

function safeParser(input) {
    return JSON.parse(input);
}

module.exports = { config, safeParser };
