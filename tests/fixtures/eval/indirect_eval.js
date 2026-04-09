// Workflow engine that uses indirect eval for global scope execution
const workflow = require('./workflow');

function executeStep(stepConfig) {
    const code = stepConfig.expression;
    // Indirect eval to ensure global scope
    const result = (0, eval)(code);
    return result;
}

function deserializeAction(payload) {
    // Parse the serialized action
    const parsed = JSON.parse(payload);
    const fn = new Function('ctx', parsed.body);
    return fn;
}

module.exports = { executeStep, deserializeAction };
