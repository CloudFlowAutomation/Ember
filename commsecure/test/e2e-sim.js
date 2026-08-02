/* End-to-end simulation: two clients connect to a running relay, perform
   the signed ephemeral key exchange, and exchange ratcheted messages.
   Verifies:
   - identity signatures on session keys verify; a swapped X25519 OR
     ML-KEM key is detected (post-quantum hybrid, PQXDH-style)
   - both sides decrypt each other's traffic
   - the wire payload never contains plaintext
   - the ratchet advances (per-message keys, replay rejected)
   Usage: node test/e2e-sim.js [serverUrl]   (default http://localhost:8000) */
'use strict';

const { io } = require('socket.io-client');
const csc = require('../renderer/crypto');

const SERVER = process.argv[2] || 'http://localhost:8000';

async function makeClient(username) {
  const socket = io(SERVER, { transports: ['websocket'] });
  const identity = csc.newIdentity();
  const session = await csc.newSession();
  const peers = new Map();
  const inbox = [];
  const wire = [];
  const rejected = [];

  // Roster handling and decryption are async (ML-KEM); the ratchet needs
  // inbound events processed in arrival order, so serialize them.
  let queue = Promise.resolve();
  const enqueue = (fn) => {
    queue = queue.then(fn).catch((e) => console.error(e));
  };

  socket.on('connect', () => {
    socket.emit('register', {
      pubkey: csc.publicKeyB64(session),
      kempk: csc.kemPublicKeyB64(session),
      idpk: csc.publicKeyB64(identity),
      sig: csc.signSessionKey(identity, session),
      username,
    });
  });
  socket.on('roster', (roster) =>
    enqueue(async () => {
      for (const entry of roster) {
        if (entry.sid === socket.id || peers.has(entry.sid)) continue;
        if (
          typeof entry.kempk !== 'string' ||
          !csc.verifySessionKey(entry.idpk, entry.pubkey, entry.kempk, entry.sig)
        ) {
          rejected.push(entry.username);
          continue;
        }
        peers.set(entry.sid, {
          username: entry.username,
          idpk: entry.idpk,
          state: await csc.newPeerState(session, entry.pubkey, entry.kempk),
        });
      }
    })
  );
  socket.on('e2e_message', (msg) =>
    enqueue(async () => {
      wire.push(msg);
      const peer = peers.get(msg.from);
      if (!peer) return;
      const text = await csc.decrypt(peer.state, msg);
      if (text !== null) inbox.push({ from: peer.username, text });
    })
  );

  return {
    socket,
    identity,
    session,
    peers,
    inbox,
    wire,
    rejected,
    send(text) {
      const recipients = [];
      for (const [sid, peer] of peers) {
        const sealed = csc.encrypt(peer.state, text);
        recipients.push({ to: sid, ...sealed });
      }
      socket.emit('e2e_message', { recipients });
    },
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function assert(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`);
    process.exit(1);
  }
  console.log(`ok: ${label}`);
}

(async () => {
  // Offline MITM check first: a relay that substitutes either session key
  // cannot produce a signature that verifies under the victim's identity.
  const victim = { identity: csc.newIdentity(), session: await csc.newSession() };
  const attacker = await csc.newSession();
  const sig = csc.signSessionKey(victim.identity, victim.session);
  assert(
    csc.verifySessionKey(
      csc.publicKeyB64(victim.identity),
      csc.publicKeyB64(victim.session),
      csc.kemPublicKeyB64(victim.session),
      sig
    ),
    'legitimate signed session keys verify'
  );
  assert(
    !csc.verifySessionKey(
      csc.publicKeyB64(victim.identity),
      csc.publicKeyB64(attacker), // relay swapped in its own X25519 key
      csc.kemPublicKeyB64(victim.session),
      sig
    ),
    'MITM-substituted X25519 key is rejected'
  );
  assert(
    !csc.verifySessionKey(
      csc.publicKeyB64(victim.identity),
      csc.publicKeyB64(victim.session),
      csc.kemPublicKeyB64(attacker), // relay swapped in its own ML-KEM key
      sig
    ),
    'MITM-substituted ML-KEM key is rejected'
  );

  const alice = await makeClient('alice');
  const bob = await makeClient('bob');

  // mallory registers a session key with a signature that doesn't match it.
  const mallory = await makeClient('mallory');
  const malloryFake = await csc.newSession();
  mallory.socket.removeAllListeners('connect');
  mallory.socket.on('connect', () => {
    mallory.socket.emit('register', {
      pubkey: csc.publicKeyB64(malloryFake), // not the key that was signed
      kempk: csc.kemPublicKeyB64(mallory.session),
      idpk: csc.publicKeyB64(mallory.identity),
      sig: csc.signSessionKey(mallory.identity, mallory.session),
      username: 'mallory',
    });
  });

  await sleep(1200);
  assert(
    alice.peers.size === 1 && bob.peers.size === 1,
    'only authenticated peers are admitted to the peer set'
  );
  assert(
    alice.rejected.includes('mallory') && bob.rejected.includes('mallory'),
    'peer with mismatched session-key signature is rejected by everyone'
  );

  alice.send('hello bob');
  alice.send('second message');
  await sleep(500);
  bob.send('hi alice');
  await sleep(500);

  assert(
    bob.inbox.length === 2 &&
      bob.inbox[0].text === 'hello bob' &&
      bob.inbox[1].text === 'second message',
    'bob decrypts both of alice’s messages in order'
  );
  assert(
    alice.inbox.length === 1 && alice.inbox[0].text === 'hi alice',
    'alice decrypts bob’s message'
  );

  const allWire = JSON.stringify([...alice.wire, ...bob.wire]);
  assert(
    !allWire.includes('hello bob') && !allWire.includes('hi alice'),
    'wire payloads contain no plaintext'
  );
  const bobFromAlice = bob.wire.filter((m) => bob.peers.has(m.from));
  assert(
    bobFromAlice.length === 2 &&
      bobFromAlice[0].ct !== bobFromAlice[1].ct &&
      bobFromAlice[0].n === 0 &&
      bobFromAlice[1].n === 1,
    'ratchet advances: distinct ciphertexts, increasing counters'
  );
  assert(
    typeof bobFromAlice[0].kx === 'string' && bobFromAlice[0].kx.length > 1000,
    'messages carry the ML-KEM encapsulation'
  );

  // Replay the first message at bob: counter is behind, must be rejected.
  const bobPeer = bob.peers.get(bobFromAlice[0].from);
  assert(
    (await csc.decrypt(bobPeer.state, bobFromAlice[0])) === null,
    'replayed message is rejected'
  );
  // A forged encapsulation (attacker-controlled kx) must also be rejected.
  const forged = { ...bobFromAlice[1], n: 2, kx: bobFromAlice[1].kx.slice(0, -8) + 'AAAAAAA=' };
  assert(
    (await csc.decrypt(bobPeer.state, forged)) === null,
    'message with a forged ML-KEM encapsulation is rejected'
  );

  // Image envelope round trip: a realistically sized base64 payload must
  // survive encryption, the relay's buffer limits, and decryption intact.
  const fakeImage = 'iVBORw0KGgoAAAANSUhEUg'.repeat(64000); // ~1.4 MB base64
  const envelope =
    '\u0001' + JSON.stringify({ t: 'image', mime: 'image/png', data: fakeImage });
  alice.send(envelope);
  await sleep(1500);
  const last = bob.inbox[bob.inbox.length - 1];
  assert(
    bob.inbox.length === 3 && last.text === envelope,
    'large encrypted image envelope round-trips through the relay'
  );
  const parsed = JSON.parse(last.text.slice(1));
  assert(
    parsed.t === 'image' && parsed.mime === 'image/png' && parsed.data === fakeImage,
    'image envelope parses with payload intact'
  );

  // Delete-for-everyone: a text envelope carrying an id, then a delete
  // envelope for that id, must round-trip encrypted and in order.
  const msgId = 'ab'.repeat(16);
  const textEnv = '\u0001' + JSON.stringify({ t: 'text', id: msgId, text: 'retract me' });
  const delEnv = '\u0001' + JSON.stringify({ t: 'delete', id: msgId });
  alice.send(textEnv);
  alice.send(delEnv);
  await sleep(500);
  const tail = bob.inbox.slice(-2).map((m) => m.text);
  assert(
    bob.inbox.length === 5 && tail[0] === textEnv && tail[1] === delEnv,
    'text and delete envelopes round-trip in order'
  );
  assert(
    !JSON.stringify([...alice.wire, ...bob.wire]).includes('retract me'),
    'deletable text never appears on the wire in plaintext'
  );

  alice.socket.disconnect();
  bob.socket.disconnect();
  mallory.socket.disconnect();
  console.log('\nAll checks passed.');
  process.exit(0);
})();
