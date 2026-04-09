// Dangerous: postMessage with wildcard targetOrigin
function sendAuthData(targetWindow) {
  const payload = {
    type: 'AUTH_DATA',
    sessionId: getSessionId(),
    token: getAuthToken(),
  };

  // BAD: any window can receive this message
  targetWindow.postMessage(payload, "*");
}

function sendToSpecific(targetWindow) {
  // GOOD: specific origin
  targetWindow.postMessage({type: 'ping'}, 'https://app.example.com');
}
