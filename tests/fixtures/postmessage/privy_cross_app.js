// Simulated @privy-io/cross-app-connect triggerPopup pattern
// This mirrors the actual vulnerable code in the published package.

var triggerPopup = function(config) {
  var popup = window.open(config.providerUri, '_blank', 'width=450,height=700');

  return new Promise(function(resolve, reject) {
    // VULNERABLE: No origin check on incoming messages
    window.addEventListener('message', function handler(o) {
      if (o.data && o.data.type === 'PRIVY_CROSS_APP_CONNECT_RESPONSE') {
        window.removeEventListener('message', handler);
        popup && popup.close();

        // Attacker can inject their own providerPublicKey here
        var providerPublicKey = o.data.providerPublicKey;
        var address = o.data.address;
        var chainType = o.data.chainType;

        // This key is used for ECDH shared secret derivation
        // If attacker controls it, they can decrypt all cross-app messages
        var sharedSecret = deriveSharedSecret(config.clientPrivateKey, providerPublicKey);

        resolve({
          address: address,
          chainType: chainType,
          sharedSecret: sharedSecret,
          expiration: o.data.exp || Date.now() + 14 * 24 * 60 * 60 * 1000,
        });
      }
    });

    // Timeout after 5 minutes
    setTimeout(function() {
      reject(new Error('Cross-app connection timed out'));
    }, 300000);
  });
};

function deriveSharedSecret(privateKey, publicKey) {
  // ECDH key exchange - attacker controls publicKey = attacker knows shared secret
  return 'shared_secret_placeholder';
}

module.exports = { triggerPopup: triggerPopup };
