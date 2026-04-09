// Vulnerable: message handler without origin check
function setupListener() {
  window.addEventListener('message', function(event) {
    // No origin check!
    if (event.data && event.data.type === 'AUTH_RESPONSE') {
      const token = event.data.accessToken;
      localStorage.setItem('auth_token', token);
    }
  });
}

setupListener();
