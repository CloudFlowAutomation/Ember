// Ember PFS crypto core — hybrid post-quantum edition.
//
// Forward secrecy comes from two layers:
//  1. Session keys are ephemeral and generated per connection — an X25519
//     keypair AND an ML-KEM-768 keypair — held only in renderer memory and
//     never written to disk.
//  2. Each pairwise direction runs a symmetric hash ratchet: every message
//     is encrypted with a one-time key derived from the current chain key,
//     and the chain immediately advances (old chain/message keys are
//     overwritten). Compromising current state cannot decrypt past traffic.
//
// Quantum resistance (PQXDH-style, as in Signal): each sender's chain root
// is H(X25519-ECDH-secret || ML-KEM-768-shared-secret). An adversary who
// records traffic today and later breaks X25519 with a quantum computer
// still lacks the ML-KEM secret; one who breaks only ML-KEM still lacks the
// ECDH secret. The KEM encapsulation travels with each message (`kx`,
// constant per session) so no extra handshake round is needed. As in
// Signal's PQXDH, the identity layer stays Ed25519 — it only authenticates,
// so breaking it later enables impersonation, never decryption of the past.
//
// Primitives: X25519 ECDH via nacl.box.before, ML-KEM-768 (FIPS 203) via
// the bundled `mlkem` library, SHA-512 for the ratchet KDF,
// XSalsa20-Poly1305 (nacl.secretbox) for message encryption.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(
      require('tweetnacl'),
      require('tweetnacl-util'),
      require('mlkem')
    );
  } else {
    root.EmberCrypto = factory(root.nacl, root.nacl.util, root.MlKemBundle);
  }
})(typeof self !== 'undefined' ? self : this, function (nacl, util, mlkem) {
  'use strict';

  const KEY_LEN = 32;
  const KEM_PK_LEN = 1184; // ML-KEM-768 public key
  const KEM_CT_LEN = 1088; // ML-KEM-768 ciphertext
  const TAG_CHAIN = 0x01; // advance the chain
  const TAG_MSG = 0x02;   // derive a one-time message key
  const TAG_ROOT = 0x0c;  // hybrid root -> sender chain

  // Domain-separation prefix so identity signatures can never be replayed
  // in another protocol or over a different message type. v2 covers both
  // session public keys, so a relay can swap neither.
  const SESSION_SIGN_CONTEXT = util.decodeUTF8('Ember-v2:session-keys:');

  const kem = new mlkem.MlKem768();

  function kdf(key, tag) {
    const input = new Uint8Array(key.length + 1);
    input.set(key);
    input[key.length] = tag;
    const out = nacl.hash(input).subarray(0, KEY_LEN);
    input.fill(0);
    return out;
  }

  // Hybrid root KDF: both secrets in, one chain key out.
  function kdf2(a, b, tag) {
    const input = new Uint8Array(a.length + b.length + 1);
    input.set(a);
    input.set(b, a.length);
    input[a.length + b.length] = tag;
    const out = nacl.hash(input).subarray(0, KEY_LEN);
    input.fill(0);
    return out;
  }

  async function newSession() {
    const box = nacl.box.keyPair();
    const [kemPublicKey, kemSecretKey] = await kem.generateKeyPair();
    return {
      publicKey: box.publicKey,
      secretKey: box.secretKey,
      kemPublicKey,
      kemSecretKey,
    };
  }

  // Pairwise ratchet state between us and one peer. Our sending chain roots
  // in the ECDH secret plus a fresh KEM secret we encapsulate to the peer's
  // ML-KEM key; the encapsulation rides along with every message we send.
  // Their sending chain is derived lazily from the first message they send
  // us (we decapsulate their `kx`), so no handshake round exists — the two
  // directions differ because each side's encapsulation is independent.
  async function newPeerState(mySession, theirPublicKeyB64, theirKemPublicKeyB64) {
    const theirPublicKey = util.decodeBase64(theirPublicKeyB64);
    const theirKemPublicKey = util.decodeBase64(theirKemPublicKeyB64);
    if (theirKemPublicKey.length !== KEM_PK_LEN) {
      throw new Error('bad ML-KEM public key length');
    }
    const dhRoot = nacl.box.before(theirPublicKey, mySession.secretKey);
    const [kemCt, kemSecret] = await kem.encap(theirKemPublicKey);
    const sendChain = kdf2(dhRoot, kemSecret, TAG_ROOT);
    kemSecret.fill(0);
    return {
      // Retained only until the peer's first message commits their chain;
      // zeroed afterwards.
      dhRoot,
      kemSecretKey: mySession.kemSecretKey,
      kemCtB64: util.encodeBase64(kemCt),
      sendChain,
      sendCount: 0,
      recvChain: null,
      recvKx: null,
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
      kx: state.kemCtB64,
      nonce: util.encodeBase64(nonce),
      ct: util.encodeBase64(box),
    };
  }

  // Ratchet forward from (chain, count) — operating on a private copy — and
  // try to open the message. Returns the advanced state only on success, so
  // a forgery can never move or corrupt the committed chain.
  function ratchetOpen(chain, count, message) {
    const n = message.n;
    if (!Number.isInteger(n) || n < count || n - count > 1000) return null;
    let c = new Uint8Array(chain);
    // Fast-forward past any messages we never received (their keys are
    // skipped and destroyed — lost messages stay unreadable, by design).
    while (count < n) {
      const next = kdf(c, TAG_CHAIN);
      c.fill(0);
      c = next;
      count++;
    }
    const messageKey = kdf(c, TAG_MSG);
    const plaintext = nacl.secretbox.open(
      util.decodeBase64(message.ct),
      util.decodeBase64(message.nonce),
      messageKey
    );
    messageKey.fill(0);
    if (!plaintext) {
      c.fill(0);
      return null;
    }
    const next = kdf(c, TAG_CHAIN);
    c.fill(0);
    return { plaintext: util.encodeUTF8(plaintext), chain: next, count: n + 1 };
  }

  async function decrypt(state, message) {
    if (typeof message.kx !== 'string') return null;
    let opened = null;
    if (state.recvChain !== null && message.kx === state.recvKx) {
      opened = ratchetOpen(state.recvChain, state.recvCount, message);
      if (!opened) return null;
    } else {
      // First message from this peer (or an unknown encapsulation): derive
      // a candidate chain and commit it only if the message authenticates.
      // ML-KEM's implicit rejection turns a forged `kx` into a random
      // secret, so the secretbox open below fails and nothing changes.
      if (state.dhRoot === null) return null;
      let kemCt;
      try {
        kemCt = util.decodeBase64(message.kx);
      } catch (e) {
        return null;
      }
      if (kemCt.length !== KEM_CT_LEN) return null;
      const kemSecret = await kem.decap(kemCt, state.kemSecretKey);
      const candidate = kdf2(state.dhRoot, kemSecret, TAG_ROOT);
      kemSecret.fill(0);
      opened = ratchetOpen(candidate, 0, message);
      candidate.fill(0);
      if (!opened) return null;
      state.recvKx = message.kx;
      state.dhRoot.fill(0);
      state.dhRoot = null; // a session's kx never legitimately changes again
    }
    if (state.recvChain) state.recvChain.fill(0);
    state.recvChain = opened.chain;
    state.recvCount = opened.count;
    return opened.plaintext;
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

  function kemPublicKeyB64(session) {
    return util.encodeBase64(session.kemPublicKey);
  }

  function destroySession(session) {
    session.secretKey.fill(0);
    session.publicKey.fill(0);
    if (session.kemSecretKey) session.kemSecretKey.fill(0);
    if (session.kemPublicKey) session.kemPublicKey.fill(0);
  }

  // ---- Persistent Ed25519 identity ----
  // The identity key only SIGNS ephemeral session keys; it never encrypts.
  // Compromising it later allows impersonation, not decryption of past
  // traffic, so forward secrecy — including against a future quantum
  // attacker — is preserved (Signal's PQXDH makes the same call).

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

  function sessionSignMessage(sessionPublicKey, kemPublicKey) {
    const msg = new Uint8Array(
      SESSION_SIGN_CONTEXT.length + sessionPublicKey.length + kemPublicKey.length
    );
    msg.set(SESSION_SIGN_CONTEXT);
    msg.set(sessionPublicKey, SESSION_SIGN_CONTEXT.length);
    msg.set(kemPublicKey, SESSION_SIGN_CONTEXT.length + sessionPublicKey.length);
    return msg;
  }

  function signSessionKey(identity, session) {
    const sig = nacl.sign.detached(
      sessionSignMessage(session.publicKey, session.kemPublicKey),
      identity.secretKey
    );
    return util.encodeBase64(sig);
  }

  function verifySessionKey(identityPublicKeyB64, sessionPublicKeyB64, kemPublicKeyB64, sigB64) {
    try {
      return nacl.sign.detached.verify(
        sessionSignMessage(
          util.decodeBase64(sessionPublicKeyB64),
          util.decodeBase64(kemPublicKeyB64)
        ),
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
    kemPublicKeyB64,
    destroySession,
    newIdentity,
    exportIdentity,
    importIdentity,
    signSessionKey,
    verifySessionKey,
  };
});
