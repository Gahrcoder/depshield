# Privy.io postMessage Origin Validation Vulnerability

**Date:** 2026-04-10
**Tool:** [depshield](https://github.com/Gahrcoder/depshield) (postMessage security analyzer + deep scan mode)
**Severity:** CRITICAL (CWE-346: Origin Validation Error)

---

## Affected Packages

| Package | Version | Severity | Finding |
|---------|---------|----------|---------|
| `@privy-io/cross-app-connect` | 0.5.6 | CRITICAL | Missing origin validation in `request.mjs` message handler |
| `@privy-io/cross-app-connect` | 0.5.6 | CRITICAL | Missing origin validation in `request.js` message handler |
| `@privy-io/cross-app-connect` | 0.5.6 | HIGH | Missing origin validation in `triggerPopup.mjs` |
| `@privy-io/cross-app-connect` | 0.5.6 | HIGH | Missing origin validation in `triggerPopup.js` |
| `@privy-io/cross-app-connect` | 0.5.6 | MEDIUM | BroadcastChannel without sender validation |
| `@privy-io/react-auth` | 3.21.0 | CRITICAL | Missing origin validation in OAuth recovery handler |
| `@privy-io/react-auth` | 3.21.0 | HIGH | postMessage sent with wildcard `"*"` targetOrigin |

## Summary

Multiple Privy.io packages register `window.addEventListener('message', ...)` handlers
that process security-sensitive data (ECDH keys, wallet addresses, OAuth tokens) without
validating `event.origin`. This allows any page that can obtain a reference to the target
window to inject forged messages.

The most critical instance is in `@privy-io/cross-app-connect`, where the cross-app
connection handshake accepts an attacker-controlled ECDH public key, enabling the
attacker to derive the shared secret used to encrypt all subsequent cross-app messages.

## depshield Scan Output

### Command

```bash
python -m depshield.cli scan /path/to/privy-project --deep --format text
```

### Results (10 findings: 4 CRITICAL, 4 HIGH, 2 MEDIUM)

```
========================================================================
  depshield scan results
========================================================================

  Packages scanned : 14
  Analyzers run    : postmessage
  Scan duration    : 0.68s
  Findings         : 10

------------------------------------------------------------------------
  [!!] #1  CRITICAL  network
  Package : @privy-io/cross-app-connect
  Missing origin validation in postMessage handler

  File registers a "message" event listener without checking
  event.origin. Any window/frame can send messages that will be
  processed by this handler. Handler processes sensitive data
  (keys/tokens/secrets).

  Evidence: window.addEventListener("message",i); ...
  Location: dist/esm/request.mjs

------------------------------------------------------------------------
  [!!] #2  CRITICAL  network
  Package : @privy-io/cross-app-connect
  Missing origin validation in postMessage handler
  Location: dist/cjs/request.js

------------------------------------------------------------------------
  [!!] #3  CRITICAL  network
  Package : @privy-io/react-auth
  Missing origin validation in postMessage handler
  Location: dist/esm/RecoveryOAuthStatusScreen-kHIPPQKH.mjs

------------------------------------------------------------------------
  [!!] #4  CRITICAL  network
  Package : @privy-io/react-auth
  Missing origin validation in postMessage handler
  Location: dist/cjs/RecoveryOAuthStatusScreen-C1VqveKl.js

------------------------------------------------------------------------
  [! ] #5  HIGH  network
  Package : @privy-io/cross-app-connect
  Missing origin validation in postMessage handler
  Location: dist/esm/triggerPopup.mjs

------------------------------------------------------------------------
  [! ] #6  HIGH  network
  Package : @privy-io/cross-app-connect
  Missing origin validation in postMessage handler
  Location: dist/cjs/triggerPopup.js

------------------------------------------------------------------------
  [! ] #7  HIGH  network
  Package : @privy-io/react-auth
  postMessage sent with wildcard targetOrigin
  Evidence: postMessage({type:ss},"*")
  Location: dist/esm/index-D9__9Tks.mjs

------------------------------------------------------------------------
  [! ] #8  HIGH  network
  Package : @privy-io/react-auth
  postMessage sent with wildcard targetOrigin
  Evidence: postMessage({type:Yt},"*")
  Location: dist/cjs/index-Dqr3wAmh.js

------------------------------------------------------------------------
  [* ] #9  MEDIUM  network
  Package : @privy-io/cross-app-connect
  BroadcastChannel without sender validation
  Location: dist/esm/triggerPopup.mjs

------------------------------------------------------------------------
  [* ] #10  MEDIUM  network
  Package : @privy-io/cross-app-connect
  BroadcastChannel without sender validation
  Location: dist/cjs/triggerPopup.js

------------------------------------------------------------------------
  Summary: 4 critical, 4 high, 2 medium
```

## Vulnerability Details

### 1. Cross-App Connect ECDH Key Injection (CRITICAL)

**File:** `@privy-io/cross-app-connect/dist/esm/request.mjs`

The SDK opens a popup for cross-app wallet connection and listens for `postMessage`
responses. The handler:
- Checks `event.data.type === 'PRIVY_CROSS_APP_CONNECT_RESPONSE'`
- Does **NOT** check `event.origin`
- Accepts `event.data.providerPublicKey` for ECDH key exchange

An attacker who can send a `postMessage` to the victim window can inject their own
ECDH public key, enabling them to:
1. Derive the same shared secret as the victim
2. Decrypt all subsequent encrypted cross-app messages
3. Forge transaction signing requests
4. Steal wallet funds

### 2. OAuth Recovery Handler Injection (CRITICAL)

**File:** `@privy-io/react-auth/dist/esm/RecoveryOAuthStatusScreen-*.mjs`

The OAuth recovery flow listens for `postMessage` events to receive OAuth callback
data. No `event.origin` validation is performed. An attacker can inject fake OAuth
error or success messages.

### 3. Wildcard targetOrigin (HIGH)

**File:** `@privy-io/react-auth/dist/esm/index-*.mjs`

The SDK sends `postMessage(data, "*")`, meaning any window that has a reference to
the target window will receive the message, regardless of origin.

### 4. BroadcastChannel Without Validation (MEDIUM)

**File:** `@privy-io/cross-app-connect/dist/esm/triggerPopup.mjs`

A `BroadcastChannel('popup-privy-oauth')` is created without validating message
senders. Any same-origin context can inject messages into this channel.

## Reproduction Steps

### 1. Install depshield and Privy packages

```bash
# Clone depshield
git clone https://github.com/Gahrcoder/depshield
cd depshield
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Create a target project with Privy
mkdir /tmp/privy-target && cd /tmp/privy-target
npm init -y
npm install @privy-io/cross-app-connect @privy-io/cross-app-provider @privy-io/react-auth @privy-io/js-sdk-core
```

### 2. Run depshield deep scan

```bash
python -m depshield.cli scan /tmp/privy-target --deep --format json
```

### 3. Run the PoC

Open `poc/privy-postmessage-poc.html` in a browser and click "Send Fake Cross-App Response".

### 4. Verify manually

Inspect the vulnerable code directly:

```bash
# Show the vulnerable handler in cross-app-connect
grep -n 'addEventListener.*message' \
  node_modules/@privy-io/cross-app-connect/dist/esm/request.mjs

# Confirm no origin check exists
grep -c 'event.origin\|e.origin\|origin.*===' \
  node_modules/@privy-io/cross-app-connect/dist/esm/request.mjs
# Output: 0
```

## Impact Analysis

| Category | Impact |
|----------|--------|
| **Confidentiality** | HIGH - Attacker can intercept ECDH shared secrets and decrypt cross-app messages |
| **Integrity** | HIGH - Attacker can forge wallet connection responses and transaction signing requests |
| **Availability** | LOW - Attacker can disrupt connection flow |
| **CVSS 3.1 (estimated)** | 8.1 (High) - Network/Low/None/Changed/High/High/None |

## Suggested Fix

All `addEventListener('message', ...)` handlers must validate `event.origin`:

```javascript
// Before (vulnerable)
window.addEventListener('message', function(event) {
  if (event.data.type === 'PRIVY_CROSS_APP_CONNECT_RESPONSE') {
    // processes event.data without origin check
  }
});

// After (fixed)
window.addEventListener('message', function(event) {
  if (event.origin !== expectedProviderOrigin) {
    return;  // reject messages from untrusted origins
  }
  if (event.data.type === 'PRIVY_CROSS_APP_CONNECT_RESPONSE') {
    // safe to process
  }
});
```

Additionally, replace `postMessage(data, "*")` with a specific target origin:

```javascript
// Before (vulnerable)
targetWindow.postMessage({type: 'STATUS'}, '*');

// After (fixed)
targetWindow.postMessage({type: 'STATUS'}, 'https://app.privy.io');
```

## Files

- **Analyzer:** [`depshield/analyzers/postmessage.py`](https://github.com/Gahrcoder/depshield/blob/main/depshield/analyzers/postmessage.py)
- **PoC:** [`poc/privy-postmessage-poc.html`](poc/privy-postmessage-poc.html)
- **Tests:** [`tests/test_analyzers/test_postmessage.py`](https://github.com/Gahrcoder/depshield/blob/main/tests/test_analyzers/test_postmessage.py)
