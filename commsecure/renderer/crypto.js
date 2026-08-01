// CommSecure PFS crypto core.
//
// Forward secrecy comes from two layers:
//  1. Session keys are ephemeral X25519 keypairs generated per connection,
//     held only in renderer memory and never written to disk.
//  2. Each pairwise direction runs a symmetric hash ratchet: every message
//     is encrypted with a one-time key derived from the current chain key,
//     and the chain immediately advances (old chain/message keys are
//     overwritten). Compromising current state cannot decrypt past traffic.
//
// Primitives (tweetnacl): X25519 ECDH via nacl.box.before, SHA-512 for the
// ratchet KDF, XSalsa20-Poly1305 (nacl.secretbox) for message encryption.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('tweetnacl'), require('tweetnacl-util'));
  } else {
    root.CommSecureCrypto = factory(root.nacl, root.nacl.util);
  }
})(typeof self !== 'undefined' ? self : this, function (nacl, util) {
  'use strict';

  const KEY_LEN = 32;
  const TAG_CHAIN = 0x01; // advance the chain
  const TAG_MSG = 0x02;   // derive a one-time message key
  const TAG_SEND_A = 0x0a;
  const TAG_SEND_B = 0x0b;

  // Domain-separation prefix so identity signatures can never be replayed
  // in another protocol or over a different message type.
  const SESSION_SIGN_CONTEXT = util.decodeUTF8('CommSecure-v1:session-key:');

  function kdf(key, tag) {
    const input = new Uint8Array(key.length + 1);
    input.set(key);
    input[key.length] = tag;
    const out = nacl.hash(input).subarray(0, KEY_LEN);
    input.fill(0);
    return out;
  }

  function compareBytes(a, b) {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
  }

  function newSession() {
    return nacl.box.keyPair();
  }

  // Pairwise ratchet state between us and one peer. Both sides derive the
  // same two chains from the ECDH root; lexicographic pubkey order decides
  // which chain each side sends on, so the assignment is symmetric.
  function newPeerState(myKeyPair, theirPublicKeyB64) {
    const theirPublicKey = util.decodeBase64(theirPublicKeyB64);
    const root = nacl.box.before(theirPublicKey, myKeyPair.secretKey);
    const chainA = kdf(root, TAG_SEND_A);
    const chainB = kdf(root, TAG_SEND_B);
    root.fill(0);
    const iSendOnA = compareBytes(myKeyPair.publicKey, theirPublicKey) < 0;
    return {
      sendChain: iSendOnA ? chainA : chainB,
      recvChain: iSendOnA ? chainB : chainA,
      sendCount: 0,
      recvCount: 0,
    };
  }

  function encrypt(state, plaintext) {
    const messageKey = kdf(state.sendChain, TAG_MSG);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const box = nacl.secretbox(util.decodeUTF8(plaintext), nonce, messageKey);
    messageKey.fill(0);
    const nextChain = kdf(state.sendChain, TAG_CHAIN);
    state.sendChain.fill(0);
    state.sendChain = nextChain;
    return {
      n: state.sendCount++,
      nonce: util.encodeBase64(nonce),
      ct: util.encodeBase64(box),
    };
  }

  function decrypt(state, message) {
    const n = message.n;
    if (!Number.isInteger(n) || n < state.recvCount || n - state.recvCount > 1000) {
      return null; // replayed, out-of-order, or absurdly far ahead
    }
    // Fast-forward past any messages we never received (their keys are
    // skipped and destroyed — lost messages stay unreadable, by design).
    while (state.recvCount < n) {
      const next = kdf(state.recvChain, TAG_CHAIN);
      state.recvChain.fill(0);
      state.recvChain = next;
      state.recvCount++;
    }
    const messageKey = kdf(state.recvChain, TAG_MSG);
    const plaintext = nacl.secretbox.open(
      util.decodeBase64(message.ct),
      util.decodeBase64(message.nonce),
      messageKey
    );
    messageKey.fill(0);
    if (!plaintext) return null; // tampered or wrong key: do not advance
    const next = kdf(state.recvChain, TAG_CHAIN);
    state.recvChain.fill(0);
    state.recvChain = next;
    state.recvCount = n + 1;
    return util.encodeUTF8(plaintext);
  }

  // Short human-checkable key fingerprint, e.g. "3f9a 12c4 88de 01b7"
  function fingerprint(publicKeyB64) {
    const digest = nacl.hash(util.decodeBase64(publicKeyB64));
    const groups = [];
    for (let i = 0; i < 8; i += 2) {
      groups.push(
        digest[i].toString(16).padStart(2, '0') +
          digest[i + 1].toString(16).padStart(2, '0')
      );
    }
    return groups.join(' ');
  }

  function publicKeyB64(keyPair) {
    return util.encodeBase64(keyPair.publicKey);
  }

  function destroySession(keyPair) {
    keyPair.secretKey.fill(0);
    keyPair.publicKey.fill(0);
  }

  // ---- Persistent Ed25519 identity ----
  // The identity key only SIGNS ephemeral session keys; it never encrypts.
  // Compromising it later allows impersonation, not decryption of past
  // traffic, so forward secrecy is preserved.

  function newIdentity() {
    return nacl.sign.keyPair();
  }

  function exportIdentity(identity) {
    return {
      publicKey: util.encodeBase64(identity.publicKey),
      secretKey: util.encodeBase64(identity.secretKey),
    };
  }

  function importIdentity(stored) {
    return {
      publicKey: util.decodeBase64(stored.publicKey),
      secretKey: util.decodeBase64(stored.secretKey),
    };
  }

  function sessionSignMessage(sessionPublicKey) {
    const msg = new Uint8Array(SESSION_SIGN_CONTEXT.length + sessionPublicKey.length);
    msg.set(SESSION_SIGN_CONTEXT);
    msg.set(sessionPublicKey, SESSION_SIGN_CONTEXT.length);
    return msg;
  }

  function signSessionKey(identity, sessionKeyPair) {
    const sig = nacl.sign.detached(
      sessionSignMessage(sessionKeyPair.publicKey),
      identity.secretKey
    );
    return util.encodeBase64(sig);
  }

  function verifySessionKey(identityPublicKeyB64, sessionPublicKeyB64, sigB64) {
    try {
      return nacl.sign.detached.verify(
        sessionSignMessage(util.decodeBase64(sessionPublicKeyB64)),
        util.decodeBase64(sigB64),
        util.decodeBase64(identityPublicKeyB64)
      );
    } catch (e) {
      return false;
    }
  }

  return {
    newSession,
    newPeerState,
    encrypt,
    decrypt,
    fingerprint,
    publicKeyB64,
    destroySession,
    newIdentity,
    exportIdentity,
    importIdentity,
    signSessionKey,
    verifySessionKey,
  };
});
