// Safe: message handler WITH origin check
const ALLOWED_ORIGIN = 'https://app.example.com';

window.addEventListener('message', function(event) {
  // Proper origin validation
  if (event.origin !== ALLOWED_ORIGIN) {
    console.warn('Rejected message from:', event.origin);
    return;
  }

  if (event.data && event.data.type === 'AUTH_RESPONSE') {
    const token = event.data.accessToken;
    localStorage.setItem('auth_token', token);
  }
});
