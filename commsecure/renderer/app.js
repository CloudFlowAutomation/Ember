/* CommSecure renderer: connection lifecycle, roster, encrypted messaging.
   Session/encryption keys live only in this renderer's memory and are
   destroyed on disconnect. The persistent Ed25519 identity key (loaded via
   the preload bridge) signs each ephemeral session key so peers can detect
   a relay that swaps public keys (MITM). */
(function () {
  'use strict';

  const csc = window.CommSecureCrypto;
  const PINS_KEY = 'commsecure-identity-pins';

  // Plaintexts starting with this control byte carry a JSON envelope
  // ({t:'text'|'image'|'file'|'delete'}, optionally {dm:true}); anything
  // else is a plain text message. Typed text is scrubbed of the byte so
  // the two can never collide.
  const ENVELOPE_PREFIX = '\u0001';
  const IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
  // Cap the base64 image payload; ciphertext grows ~4/3 per recipient copy
  // and the relay/websocket layers have finite frame limits.
  const IMAGE_DATA_CAP = 1500000;
  const IMAGE_PASSTHROUGH_BYTES = 900 * 1024;
  // Non-image files travel the same E2E pipeline but can't be compressed,
  // so they get a hard byte cap (~1.4 MB -> ~1.9 MB base64).
  const FILE_BYTES_CAP = 1400 * 1024;
  const FILE_DATA_CAP = 2000000;
  const FILE_NAME_MAX = 120;

  const connectScreen = document.getElementById('connect-screen');
  const chatScreen = document.getElementById('chat-screen');
  const connectForm = document.getElementById('connect-form');
  const connectError = document.getElementById('connect-error');
  const usernameInput = document.getElementById('username');
  const settingsToggleBtn = document.getElementById('settings-toggle');
  const settingsPanel = document.getElementById('settings-panel');
  const serverUrlSetting = document.getElementById('server-url-setting');
  const lobbyUrlSetting = document.getElementById('lobby-url-setting');
  const modeDirectBtn = document.getElementById('mode-direct');
  const modeRoomBtn = document.getElementById('mode-room');
  const roomFields = document.getElementById('room-fields');
  const joinCodeInput = document.getElementById('join-code');
  const roomDurationInput = document.getElementById('room-duration');
  const roomAllowExtendInput = document.getElementById('room-allow-extend');
  const createRoomBtn = document.getElementById('create-room-btn');
  const roomInfoEl = document.getElementById('room-info');
  const selfNameEl = document.getElementById('self-name');
  const selfFingerprintEl = document.getElementById('self-fingerprint');
  const rosterEl = document.getElementById('roster');
  const rosterCountEl = document.getElementById('roster-count');
  const messagesEl = document.getElementById('messages');
  const composer = document.getElementById('composer');
  const messageInput = document.getElementById('message-input');
  const attachBtn = document.getElementById('attach-btn');
  const imageInput = document.getElementById('image-input');
  const disconnectBtn = document.getElementById('disconnect-btn');
  const chatTitleEl = document.getElementById('chat-title');
  const roomTimerEl = document.getElementById('room-timer');
  const roomTimerText = document.getElementById('room-timer-text');
  const extendBtn = document.getElementById('extend-btn');
  const extendMenu = document.getElementById('extend-menu');
  const endRoomBtn = document.getElementById('end-room-btn');
  const dmIndicator = document.getElementById('dm-indicator');
  const dmNameEl = document.getElementById('dm-name');
  const dmClearBtn = document.getElementById('dm-clear');

  let socket = null;
  let session = null;   // ephemeral X25519 + ML-KEM-768 keys for this connection
  let identity = null;  // persistent Ed25519 signing keypair
  let username = '';
  // sid -> { username, pubkey, idpk, fingerprint, status, state }
  const peers = new Map();
  // "sender:id" -> message element, so delete envelopes can find their
  // target. Keyed by sender so a peer can only ever delete its own messages.
  const messageIndex = new Map();
  // Direct-message state: the roster peer the composer is addressed to
  // (null = everyone), and own message id -> DM recipient sid so a later
  // "delete for everyone" goes only where the message went.
  let dmTarget = null;
  const dmSentTargets = new Map();
  // Private-room metadata: { code, name, expiresAt (ms), hostKey|null }.
  let roomMeta = null;
  let roomTimerInterval = null;

  function newMessageId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function isValidMessageId(id) {
    return typeof id === 'string' && /^[0-9a-f]{16,64}$/.test(id);
  }

  function msgKey(sender, id) {
    return sender + ':' + id;
  }

  // ---- Identity bootstrap (blocks the connect button until ready) ----

  const connectButton = connectForm.querySelector('button');
  connectButton.disabled = true;

  (async () => {
    try {
      const stored = await window.secureStore.loadIdentity();
      if (stored && stored.publicKey && stored.secretKey) {
        identity = csc.importIdentity(stored);
      } else {
        identity = csc.newIdentity();
        await window.secureStore.saveIdentity(csc.exportIdentity(identity));
      }
      connectButton.disabled = false;
    } catch (e) {
      showError('Could not load or create your identity key: ' + e.message);
    }
  })();

  // ---- TOFU pin store: username -> identity public key (base64) ----

  function loadPins() {
    try {
      return JSON.parse(localStorage.getItem(PINS_KEY)) || {};
    } catch (e) {
      return {};
    }
  }

  function pinStatus(entry) {
    const pins = loadPins();
    const pinned = pins[entry.username];
    if (!pinned) {
      pins[entry.username] = entry.idpk;
      localStorage.setItem(PINS_KEY, JSON.stringify(pins));
      return 'new';
    }
    return pinned === entry.idpk ? 'pinned' : 'changed';
  }

  function showError(text) {
    connectError.textContent = text;
    connectError.classList.remove('hidden');
  }

  function fmtBytes(n) {
    if (!Number.isFinite(n) || n < 0) return '';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function addMessage({ id, from, author, text, image, file, own, system, warning, dm, dmName }) {
    const div = document.createElement('div');
    div.className =
      'msg' + (own ? ' own' : '') + (system ? ' system' : '') + (warning ? ' warning' : '') +
      (dm ? ' dm' : '');
    if (!system) {
      const meta = document.createElement('div');
      meta.className = 'msg-meta';
      const authorEl = document.createElement('span');
      authorEl.className = 'msg-author';
      authorEl.textContent = author;
      const time = document.createElement('span');
      time.textContent = new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      });
      meta.append(authorEl, time);
      if (dm) {
        const tag = document.createElement('span');
        tag.className = 'msg-dm-tag';
        tag.textContent = own && dmName ? '🔒 to ' + dmName : '🔒 private';
        meta.appendChild(tag);
      }
      if (own && id) {
        const del = document.createElement('button');
        del.type = 'button';
        del.className = 'msg-delete';
        del.title = 'Delete for everyone';
        del.setAttribute('aria-label', 'Delete for everyone');
        del.textContent = '🗑';
        del.addEventListener('click', () => deleteForEveryone(id));
        meta.appendChild(del);
      }
      div.appendChild(meta);
    }
    const body = document.createElement('div');
    body.className = 'msg-body';
    if (image) {
      const img = document.createElement('img');
      img.className = 'msg-image';
      img.alt = 'encrypted image';
      img.src = image;
      img.addEventListener('load', () => {
        messagesEl.scrollTop = messagesEl.scrollHeight;
      });
      img.addEventListener('click', () => openLightbox(img.src));
      body.appendChild(img);
    } else if (file) {
      const card = document.createElement('div');
      card.className = 'msg-file';
      const icon = document.createElement('span');
      icon.className = 'msg-file-icon';
      icon.textContent = '📄';
      const info = document.createElement('div');
      info.className = 'msg-file-info';
      const nameEl = document.createElement('div');
      nameEl.className = 'msg-file-name';
      nameEl.textContent = file.name;
      const sizeEl = document.createElement('div');
      sizeEl.className = 'msg-file-size';
      sizeEl.textContent = fmtBytes(file.size);
      info.append(nameEl, sizeEl);
      const save = document.createElement('button');
      save.type = 'button';
      save.className = 'msg-file-save';
      save.textContent = 'Save';
      save.addEventListener('click', () => {
        // Always serve as an opaque download — never let received content
        // render or execute in the app's origin.
        const a = document.createElement('a');
        a.href = 'data:application/octet-stream;base64,' + file.data;
        a.download = file.name;
        a.click();
      });
      card.append(icon, info, save);
      body.appendChild(card);
    } else {
      body.textContent = text;
    }
    div.appendChild(body);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    if (id) {
      messageIndex.set(msgKey(own ? 'self' : from, id), div);
      if (own) div.dataset.mid = id; // lets the context menu find the id
    }
  }

  // Replace a message's content with a tombstone. The bubble stays so the
  // conversation makes it clear a message existed and was retracted.
  function tombstoneMessage(el) {
    if (el.classList.contains('deleted')) return;
    el.classList.add('deleted');
    const btn = el.querySelector('.msg-delete');
    if (btn) btn.remove();
    el.querySelector('.msg-body').textContent = 'This message was deleted';
  }

  function deleteForEveryone(id) {
    const el = messageIndex.get(msgKey('self', id));
    if (!el || el.classList.contains('deleted')) return;
    // A DM's retraction goes only to the peer who received the original.
    sendEncrypted(ENVELOPE_PREFIX + JSON.stringify({ t: 'delete', id }), dmSentTargets.get(id));
    tombstoneMessage(el);
  }

  const STATUS_LABEL = {
    pinned: '✓ known identity',
    new: 'new identity (pinned)',
    changed: '⚠ identity changed!',
    invalid: '⚠ invalid signature',
  };

  // Choose (or clear) the peer the composer sends privately to.
  function setDmTarget(sid) {
    const peer = sid ? peers.get(sid) : null;
    if (sid && (!peer || !peer.state)) return; // never DM an unauthenticated key
    dmTarget = sid;
    dmNameEl.textContent = peer ? peer.username : '';
    dmIndicator.classList.toggle('hidden', !sid);
    messageInput.placeholder = peer
      ? 'Send a private encrypted message to ' + peer.username + '…'
      : 'Send an encrypted message…';
    renderRoster();
    messageInput.focus();
  }

  function renderRoster() {
    rosterEl.textContent = '';
    for (const [sid, peer] of peers) {
      const li = document.createElement('li');
      li.className = 'peer-' + peer.status + (sid === dmTarget ? ' dm-selected' : '');
      const name = document.createElement('div');
      name.className = 'peer-name';
      name.textContent = peer.username;
      const fp = document.createElement('div');
      fp.className = 'peer-fingerprint';
      fp.textContent = peer.fingerprint;
      const status = document.createElement('div');
      status.className = 'peer-status peer-status-' + peer.status;
      status.textContent = STATUS_LABEL[peer.status];
      li.append(name, fp, status);
      if (peer.state) {
        li.classList.add('dm-able');
        li.title =
          sid === dmTarget
            ? 'Click to go back to messaging everyone'
            : 'Click to message ' + peer.username + ' privately';
        li.addEventListener('click', () => setDmTarget(sid === dmTarget ? null : sid));
      }
      rosterEl.appendChild(li);
    }
    rosterCountEl.textContent = String(peers.size + 1); // + self
  }

  async function handleRoster(roster) {
    if (!socket || !session) return;
    const seen = new Set();
    for (const entry of roster) {
      if (entry.sid === socket.id) continue;
      seen.add(entry.sid);
      const existing = peers.get(entry.sid);
      if (existing && existing.pubkey === entry.pubkey && existing.idpk === entry.idpk) {
        existing.username = entry.username;
        continue;
      }

      // Authenticate the session keys before trusting them: the identity
      // key must have signed BOTH the X25519 and ML-KEM keys. A relay
      // swapping either one fails here. Clients without a post-quantum key
      // fail too (they predate the v2 signing context).
      let state = null;
      if (
        typeof entry.kempk === 'string' &&
        csc.verifySessionKey(entry.idpk, entry.pubkey, entry.kempk, entry.sig)
      ) {
        try {
          state = await csc.newPeerState(session, entry.pubkey, entry.kempk);
        } catch (e) {
          state = null;
        }
      }
      if (!state) {
        peers.set(entry.sid, {
          username: entry.username,
          pubkey: entry.pubkey,
          idpk: entry.idpk,
          fingerprint: csc.fingerprint(entry.idpk),
          status: 'invalid',
          state: null, // never encrypt to an unauthenticated key
        });
        addMessage({
          system: true,
          warning: true,
          text: `Warning: "${entry.username}" presented session keys their identity did not sign (or an outdated client without post-quantum keys) — possible MITM. They are excluded from your messages.`,
        });
        continue;
      }

      const status = pinStatus(entry);
      peers.set(entry.sid, {
        username: entry.username,
        pubkey: entry.pubkey,
        idpk: entry.idpk,
        fingerprint: csc.fingerprint(entry.idpk),
        status,
        state,
      });
      if (status === 'changed') {
        addMessage({
          system: true,
          warning: true,
          text: `Warning: "${entry.username}" has a DIFFERENT identity key than before. Verify their fingerprint out-of-band before trusting this conversation.`,
        });
      } else {
        addMessage({ system: true, text: `${entry.username} joined the room` });
      }
    }
    for (const [sid, peer] of peers) {
      if (!seen.has(sid)) {
        peers.delete(sid);
        if (sid === dmTarget) setDmTarget(null);
        addMessage({ system: true, text: `${peer.username} left the room` });
      }
    }
    renderRoster();
  }

  function teardown() {
    if (socket) {
      socket.removeAllListeners();
      socket.disconnect();
      socket = null;
    }
    if (session) {
      csc.destroySession(session);
      session = null;
    }
    peers.clear();
    messageIndex.clear();
    dmSentTargets.clear();
    setDmTarget(null);
    stopRoomTimer();
    roomMeta = null;
    messagesEl.textContent = '';
    rosterEl.textContent = '';
    chatScreen.classList.add('hidden');
    connectScreen.classList.remove('hidden');
  }

  // ---- Settings (persisted) ----

  // Both endpoints are user-configurable in the Settings panel and persist
  // across sessions; blank falls back to the default. The lobby is the
  // control plane that provisions each private room's MicroVM.
  const DEFAULT_SERVER_URL = 'http://localhost:8000';
  const DEFAULT_LOBBY_URL = 'http://localhost:8100';
  const SETTINGS_KEY = 'commsecure-settings';

  function loadSettings() {
    try {
      return JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {};
    } catch (e) {
      return {};
    }
  }

  function saveSettings(patch) {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(Object.assign(loadSettings(), patch)));
  }

  function serverUrl() {
    const custom = (loadSettings().serverUrl || '').trim();
    return custom || DEFAULT_SERVER_URL;
  }

  function lobbyUrl() {
    const custom = (loadSettings().lobbyUrl || '').trim();
    return custom || DEFAULT_LOBBY_URL;
  }

  settingsToggleBtn.addEventListener('click', () => {
    settingsPanel.classList.toggle('hidden');
  });

  serverUrlSetting.value = loadSettings().serverUrl || '';
  serverUrlSetting.addEventListener('change', () => {
    saveSettings({ serverUrl: serverUrlSetting.value.trim() });
  });

  lobbyUrlSetting.value = loadSettings().lobbyUrl || '';
  lobbyUrlSetting.addEventListener('change', () => {
    saveSettings({ lobbyUrl: lobbyUrlSetting.value.trim() });
  });

  // ---- Host keys (persisted so the creator can still extend after an
  // app restart). Entries are pruned at the 8 h platform lifetime cap. ----

  const HOSTKEYS_KEY = 'commsecure-host-keys';

  function normCode(code) {
    return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  function loadHostKeys() {
    try {
      return JSON.parse(localStorage.getItem(HOSTKEYS_KEY)) || {};
    } catch (e) {
      return {};
    }
  }

  function saveHostKey(code, key) {
    const all = loadHostKeys();
    const now = Date.now();
    for (const c of Object.keys(all)) {
      if (!all[c] || all[c].exp < now) delete all[c];
    }
    all[normCode(code)] = { key, exp: now + 480 * 60000 };
    localStorage.setItem(HOSTKEYS_KEY, JSON.stringify(all));
  }

  function hostKeyFor(code) {
    const entry = loadHostKeys()[normCode(code)];
    return entry && entry.exp > Date.now() ? entry.key : null;
  }

  // ---- Room countdown (chat header) ----

  function fmtRemaining(ms) {
    if (ms <= 0) return 'expiring…';
    const totalSec = Math.ceil(ms / 1000);
    if (totalSec < 60) return totalSec + ' s left';
    const min = Math.floor(totalSec / 60);
    if (min < 60) return min + ' min left';
    return Math.floor(min / 60) + ' h ' + (min % 60) + ' min left';
  }

  function updateRoomTimer() {
    if (roomMeta) roomTimerText.textContent = fmtRemaining(roomMeta.expiresAt - Date.now());
  }

  function startRoomTimer() {
    stopRoomTimer();
    roomTimerEl.classList.remove('hidden');
    // Only the creator holds the host key, so only they see Extend — and
    // only when the room was created with extensions enabled. End room is
    // creator-only too, but works regardless of the extend setting.
    extendBtn.classList.toggle('hidden', !(roomMeta.hostKey && roomMeta.allowExtend));
    endRoomBtn.classList.toggle('hidden', !roomMeta.hostKey);
    updateRoomTimer();
    roomTimerInterval = setInterval(updateRoomTimer, 1000);
  }

  function stopRoomTimer() {
    if (roomTimerInterval) {
      clearInterval(roomTimerInterval);
      roomTimerInterval = null;
    }
    roomTimerEl.classList.add('hidden');
    extendMenu.classList.add('hidden');
  }

  let mode = 'direct';

  function setMode(next) {
    mode = next;
    modeDirectBtn.classList.toggle('active', next === 'direct');
    modeRoomBtn.classList.toggle('active', next === 'room');
    roomFields.classList.toggle('hidden', next !== 'room');
  }

  modeDirectBtn.addEventListener('click', () => setMode('direct'));
  modeRoomBtn.addEventListener('click', () => setMode('room'));

  function setRoomInfo(text) {
    roomInfoEl.textContent = text;
    roomInfoEl.classList.toggle('hidden', !text);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function lobbyFetch(base, path, body, headers, method) {
    let res;
    try {
      res = await fetch(base.replace(/\/+$/, '') + path, {
        method: method || (body === undefined ? 'GET' : 'POST'),
        headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e) {
      throw new Error('Could not reach the lobby at ' + base);
    }
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(
        typeof payload.detail === 'string' ? payload.detail : 'Lobby error (HTTP ' + res.status + ')'
      );
    }
    return payload;
  }

  createRoomBtn.addEventListener('click', async () => {
    const minutes = parseInt(roomDurationInput.value, 10);
    if (!minutes) return;
    createRoomBtn.disabled = true;
    setRoomInfo('Creating room…');
    try {
      const allowExtend = roomAllowExtendInput.checked;
      const room = await lobbyFetch(lobbyUrl(), '/rooms', {
        duration_minutes: minutes,
        allow_extend: allowExtend,
      });
      // Keeping the host key marks us as this room's creator: it unlocks
      // the Extend control in the chat header.
      saveHostKey(room.join_code, room.host_key);
      joinCodeInput.value = room.join_code;
      setRoomInfo(
        'Room created — share code ' + room.join_code +
        '. It expires at ' + new Date(room.expires_at).toLocaleTimeString() +
        ' and closes early after 10 minutes without messages.' +
        (allowExtend
          ? ' As its creator you can extend it from inside the room.'
          : ' It cannot be extended.')
      );
    } catch (err) {
      setRoomInfo('Could not create room: ' + err.message);
    } finally {
      createRoomBtn.disabled = false;
    }
  });

  // Exchange a join code for the room's endpoint URL and a platform auth
  // token that expires with the room; wait out the VM's cold start.
  async function joinPrivateRoom(lobby, code) {
    setRoomInfo('Looking up room…');
    const join = await lobbyFetch(lobby, '/rooms/join', { code });
    let state = join.state;
    const deadline = Date.now() + 90000;
    while (state === 'PENDING' && Date.now() < deadline) {
      setRoomInfo('Room is starting…');
      await sleep(2000);
      const status = await lobbyFetch(lobby, '/rooms/' + encodeURIComponent(code.replace(/[^A-Za-z0-9]/g, '')));
      state = status.state;
    }
    if (state === 'PENDING') throw new Error('The room did not start in time. Try again.');
    setRoomInfo('Joining "' + join.name + '" — room expires at ' + new Date(join.expires_at).toLocaleTimeString());
    return join;
  }

  connectForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!identity || socket) return;
    connectError.classList.add('hidden');
    username = usernameInput.value.trim();
    if (!username) return;

    if (mode === 'direct') {
      roomMeta = null;
      openSocket(serverUrl(), {});
      return;
    }

    const code = joinCodeInput.value.trim();
    if (!code) {
      setRoomInfo('Enter a join code, or create a room first.');
      return;
    }
    connectButton.disabled = true;
    try {
      const join = await joinPrivateRoom(lobbyUrl(), code);
      roomMeta = {
        code: normCode(code),
        name: join.name,
        expiresAt: Date.parse(join.expires_at),
        hostKey: hostKeyFor(code),
        // Older lobbies don't send allow_extend; treat missing as allowed.
        allowExtend: join.allow_extend !== false,
      };
      // The MicroVM endpoint authenticates the WebSocket via these
      // subprotocols (browser sockets can't set headers); Lambda strips
      // them before the request reaches the relay.
      openSocket(join.url, { protocols: join.subprotocols });
    } catch (err) {
      showError(err.message);
    } finally {
      connectButton.disabled = false;
    }
  });

  function openSocket(url, extraOpts) {
    socket = io(url, Object.assign({ transports: ['websocket'], reconnection: false }, extraOpts));

    // Roster handling and decryption are async (ML-KEM encap/decap), but
    // the ratchet depends on processing a sender's messages in arrival
    // order — so every inbound event runs through one serial queue.
    let inboundQueue = Promise.resolve();
    function enqueue(fn) {
      inboundQueue = inboundQueue.then(fn).catch((e) => console.error('inbound handler:', e));
    }

    socket.on('connect', () => {
      enqueue(async () => {
        // Fresh ephemeral keys per connection (forward secrecy) — X25519
        // plus ML-KEM-768 for post-quantum hybrid agreement — both signed
        // by the persistent identity key (authenticity).
        session = await csc.newSession();
        socket.emit('register', {
          pubkey: csc.publicKeyB64(session),
          kempk: csc.kemPublicKeyB64(session),
          idpk: csc.publicKeyB64(identity),
          sig: csc.signSessionKey(identity, session),
          username: username,
        });
        selfNameEl.textContent = username + ' (you)';
        selfFingerprintEl.textContent = csc.fingerprint(csc.publicKeyB64(identity));
        chatTitleEl.textContent = roomMeta ? roomMeta.name : 'Community room';
        if (roomMeta) startRoomTimer();
        connectScreen.classList.add('hidden');
        chatScreen.classList.remove('hidden');
        messageInput.focus();
        addMessage({
          system: true,
          text: 'Connected. Messages are end-to-end encrypted with perfect forward secrecy; session keys use hybrid X25519 + ML-KEM-768 (post-quantum) agreement and are signed by persistent identities.',
        });
      });
    });

    socket.on('connect_error', (err) => {
      showError(`Could not connect: ${err.message}`);
      teardown();
    });

    socket.on('disconnect', () => {
      if (session) {
        addMessage({ system: true, text: 'Disconnected from server.' });
        teardown();
        showError('Connection lost. Your session keys were destroyed.');
      }
    });

    socket.on('roster', (roster) => enqueue(() => handleRoster(roster)));

    async function handleInbound(msg) {
      const peer = peers.get(msg.from);
      if (!peer || !peer.state) return; // unknown or unauthenticated sender
      const plaintext = await csc.decrypt(peer.state, msg);
      if (plaintext === null) return; // replay, tamper, or desync: drop
      if (plaintext.startsWith(ENVELOPE_PREFIX)) {
        let envelope;
        try {
          envelope = JSON.parse(plaintext.slice(ENVELOPE_PREFIX.length));
        } catch (e) {
          return; // malformed envelope: drop
        }
        if (!envelope) return;
        const dm = envelope.dm === true;
        if (
          envelope.t === 'image' &&
          IMAGE_MIMES.has(envelope.mime) &&
          typeof envelope.data === 'string' &&
          envelope.data.length <= IMAGE_DATA_CAP &&
          /^[A-Za-z0-9+/=]+$/.test(envelope.data)
        ) {
          addMessage({
            id: isValidMessageId(envelope.id) ? envelope.id : null,
            from: msg.from,
            author: peer.username,
            image: `data:${envelope.mime};base64,${envelope.data}`,
            dm,
          });
        } else if (
          envelope.t === 'text' &&
          typeof envelope.text === 'string' &&
          envelope.text.length > 0
        ) {
          addMessage({
            id: isValidMessageId(envelope.id) ? envelope.id : null,
            from: msg.from,
            author: peer.username,
            text: envelope.text,
            dm,
          });
        } else if (
          envelope.t === 'file' &&
          typeof envelope.name === 'string' &&
          envelope.name.length > 0 &&
          typeof envelope.data === 'string' &&
          envelope.data.length > 0 &&
          envelope.data.length <= FILE_DATA_CAP &&
          /^[A-Za-z0-9+/=]+$/.test(envelope.data)
        ) {
          addMessage({
            id: isValidMessageId(envelope.id) ? envelope.id : null,
            from: msg.from,
            author: peer.username,
            file: {
              name: envelope.name.replace(/[\\/]/g, '_').slice(0, FILE_NAME_MAX),
              size: typeof envelope.size === 'number' ? envelope.size : null,
              data: envelope.data,
            },
            dm,
          });
        } else if (envelope.t === 'delete' && isValidMessageId(envelope.id)) {
          // Deletes arrive over the sender's authenticated channel and the
          // index is keyed by sender sid, so a peer can only retract its
          // own messages.
          const el = messageIndex.get(msgKey(msg.from, envelope.id));
          if (el) tombstoneMessage(el);
        }
        return; // unknown envelope types are dropped, not shown as text
      }
      addMessage({ author: peer.username, text: plaintext });
    }

    socket.on('e2e_message', (msg) => enqueue(() => handleInbound(msg)));

    socket.on('room_extended', (info) => {
      const ts = info && Number(info.expires_at);
      if (!roomMeta || !Number.isFinite(ts)) return;
      roomMeta.expiresAt = ts * 1000;
      updateRoomTimer();
      addMessage({
        system: true,
        text: 'The host extended the room — it now expires at ' +
          new Date(roomMeta.expiresAt).toLocaleTimeString() + '.',
      });
    });

    socket.on('room_closed', (info) => {
      const kind = info && info.reason;
      const reason = kind === 'idle'
        ? 'the room was idle for 10 minutes'
        : kind === 'ended'
          ? 'the host ended the room'
          : 'the room reached its expiration';
      addMessage({ system: true, text: 'Room closed — ' + reason + '.' });
    });
  }

  // Encrypt an independent copy of the plaintext for each authenticated
  // peer and fan it out through the relay. With `onlySid` set, exactly one
  // peer receives a copy — that is all a direct message is; nobody else
  // (relay included) ever holds ciphertext addressed to them.
  function sendEncrypted(plaintext, onlySid) {
    const recipients = [];
    for (const [sid, peer] of peers) {
      if (!peer.state) continue;
      if (onlySid && sid !== onlySid) continue;
      const sealed = csc.encrypt(peer.state, plaintext);
      recipients.push({ to: sid, n: sealed.n, kx: sealed.kx, nonce: sealed.nonce, ct: sealed.ct });
    }
    if (recipients.length > 0) {
      socket.emit('e2e_message', { recipients });
    }
    return recipients.length;
  }

  // Wrap an envelope for the composer's current audience (everyone, or the
  // selected DM peer). Returns display extras for the local echo.
  function sendEnvelope(envelope) {
    const target = dmTarget && peers.has(dmTarget) ? dmTarget : null;
    if (target) envelope.dm = true;
    sendEncrypted(ENVELOPE_PREFIX + JSON.stringify(envelope), target || undefined);
    if (target && envelope.id) dmSentTargets.set(envelope.id, target);
    return target ? { dm: true, dmName: peers.get(target).username } : {};
  }

  composer.addEventListener('submit', (e) => {
    e.preventDefault();
    // Strip the envelope prefix byte so typed text can never masquerade as
    // a structured payload.
    const text = messageInput.value.replace(/\u0001/g, '');
    if (!text || !socket || !session) return;
    messageInput.value = '';
    // Text travels in an id-carrying envelope so it can later be deleted
    // for everyone; bare plaintext from older clients is still accepted.
    const id = newMessageId();
    const extras = sendEnvelope({ t: 'text', id, text });
    addMessage(Object.assign({ id, author: username, text, own: true }, extras));
  });

  // ---- Image sending ----
  // Images travel the same E2E pipeline as text: the data URL payload is
  // wrapped in a JSON envelope and encrypted per peer. Small files are sent
  // as-is (preserving PNG transparency / GIF animation); larger ones are
  // downscaled and re-encoded as JPEG until they fit the payload cap.

  async function fileToDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
  }

  async function compressToDataUrl(file) {
    const bitmap = await createImageBitmap(file);
    try {
      for (const maxSide of [1600, 1152, 800, 560]) {
        const scale = Math.min(1, maxSide / Math.max(bitmap.width, bitmap.height));
        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round(bitmap.width * scale));
        canvas.height = Math.max(1, Math.round(bitmap.height * scale));
        canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        const url = canvas.toDataURL('image/jpeg', 0.82);
        if (url.length <= IMAGE_DATA_CAP) return url;
      }
      return null;
    } finally {
      bitmap.close();
    }
  }

  async function sendImageFile(file) {
    if (!socket || !session || !file || !IMAGE_MIMES.has(file.type)) return;
    attachBtn.disabled = true;
    try {
      const dataUrl =
        file.size <= IMAGE_PASSTHROUGH_BYTES
          ? await fileToDataUrl(file)
          : await compressToDataUrl(file);
      if (!dataUrl || dataUrl.length > IMAGE_DATA_CAP + 64) {
        addMessage({
          system: true,
          warning: true,
          text: 'Image is too large to send, even after compression.',
        });
        return;
      }
      const [header, data] = dataUrl.split(',', 2);
      const mime = header.slice('data:'.length, header.indexOf(';'));
      if (!IMAGE_MIMES.has(mime) || !data) return;
      const id = newMessageId();
      const extras = sendEnvelope({ t: 'image', id, mime, data });
      addMessage(Object.assign({ id, author: username, image: dataUrl, own: true }, extras));
    } catch (e) {
      addMessage({
        system: true,
        warning: true,
        text: 'Could not read that image: ' + e.message,
      });
    } finally {
      attachBtn.disabled = false;
    }
  }

  // Any other file rides the same encrypted pipeline as an opaque
  // base64 payload the recipient can save; there is no compression path,
  // so oversized files are refused up front.
  async function sendGenericFile(file) {
    if (!socket || !session || !file) return;
    if (file.size > FILE_BYTES_CAP) {
      addMessage({
        system: true,
        warning: true,
        text: 'That file is too large to send (limit ' + fmtBytes(FILE_BYTES_CAP) + ').',
      });
      return;
    }
    attachBtn.disabled = true;
    try {
      const dataUrl = await fileToDataUrl(file);
      const data = dataUrl.slice(dataUrl.indexOf(',') + 1);
      if (!data) {
        addMessage({ system: true, warning: true, text: 'That file is empty or unreadable.' });
        return;
      }
      if (data.length > FILE_DATA_CAP) {
        addMessage({ system: true, warning: true, text: 'That file is too large to send.' });
        return;
      }
      const name = (file.name || 'file').replace(/[\\/]/g, '_').slice(0, FILE_NAME_MAX);
      const id = newMessageId();
      const extras = sendEnvelope({ t: 'file', id, name, size: file.size, data });
      addMessage(
        Object.assign({ id, author: username, file: { name, size: file.size, data }, own: true }, extras)
      );
    } catch (e) {
      addMessage({
        system: true,
        warning: true,
        text: 'Could not read that file: ' + e.message,
      });
    } finally {
      attachBtn.disabled = false;
    }
  }

  attachBtn.addEventListener('click', () => imageInput.click());

  imageInput.addEventListener('change', () => {
    const file = imageInput.files && imageInput.files[0];
    imageInput.value = '';
    if (!file) return;
    if (IMAGE_MIMES.has(file.type)) sendImageFile(file);
    else sendGenericFile(file);
  });

  // Pasting an image into the composer sends it too.
  messageInput.addEventListener('paste', (e) => {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
      if (item.kind === 'file' && IMAGE_MIMES.has(item.type)) {
        e.preventDefault();
        sendImageFile(item.getAsFile());
        return;
      }
    }
  });

  // ---- Media lightbox ----
  // Clicking media in a message pops it out full size; click anywhere or
  // press Escape to close. Lives on <body>, so it survives chat teardown.

  const lightbox = document.createElement('div');
  lightbox.className = 'lightbox hidden';
  const lightboxImg = document.createElement('img');
  lightboxImg.alt = 'full-size image';
  lightbox.appendChild(lightboxImg);
  document.body.appendChild(lightbox);

  function openLightbox(src) {
    lightboxImg.src = src;
    lightbox.classList.remove('hidden');
  }

  function closeLightbox() {
    lightbox.classList.add('hidden');
    lightboxImg.removeAttribute('src');
  }

  lightbox.addEventListener('click', closeLightbox);
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeLightbox();
  });

  // ---- Right-click "Delete for everyone" on your own messages ----
  // Electron windows have no native context menu, so a themed DOM menu
  // stands in. It only opens on non-deleted own messages.

  const ctxMenu = document.createElement('div');
  ctxMenu.className = 'context-menu hidden';
  const ctxDelete = document.createElement('button');
  ctxDelete.type = 'button';
  ctxDelete.className = 'context-menu-item';
  ctxDelete.textContent = 'Delete for everyone';
  ctxMenu.appendChild(ctxDelete);
  document.body.appendChild(ctxMenu);
  let ctxTargetId = null;

  function hideContextMenu() {
    ctxTargetId = null;
    ctxMenu.classList.add('hidden');
  }

  messagesEl.addEventListener('contextmenu', (e) => {
    const msgEl = e.target.closest('.msg.own');
    if (!msgEl || !msgEl.dataset.mid || msgEl.classList.contains('deleted')) {
      hideContextMenu();
      return;
    }
    e.preventDefault();
    ctxTargetId = msgEl.dataset.mid;
    ctxMenu.classList.remove('hidden');
    const rect = ctxMenu.getBoundingClientRect();
    ctxMenu.style.left = Math.min(e.clientX, window.innerWidth - rect.width - 8) + 'px';
    ctxMenu.style.top = Math.min(e.clientY, window.innerHeight - rect.height - 8) + 'px';
  });

  ctxDelete.addEventListener('click', () => {
    if (ctxTargetId) deleteForEveryone(ctxTargetId);
    hideContextMenu();
  });

  // Any interaction outside the menu dismisses it.
  window.addEventListener('mousedown', (e) => {
    if (!ctxMenu.contains(e.target)) hideContextMenu();
  });
  window.addEventListener('blur', hideContextMenu);
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideContextMenu();
  });
  messagesEl.addEventListener('scroll', hideContextMenu);

  // ---- Room extension (creator only) ----

  extendBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    extendMenu.classList.toggle('hidden');
  });

  window.addEventListener('mousedown', (e) => {
    if (!extendMenu.contains(e.target) && e.target !== extendBtn) {
      extendMenu.classList.add('hidden');
    }
  });

  async function extendRoom(minutes) {
    extendMenu.classList.add('hidden');
    if (!roomMeta || !roomMeta.hostKey || !roomMeta.allowExtend) return;
    extendBtn.disabled = true;
    try {
      const res = await lobbyFetch(
        lobbyUrl(),
        '/rooms/' + encodeURIComponent(roomMeta.code) + '/extend',
        { additional_minutes: minutes },
        { 'X-Host-Key': roomMeta.hostKey }
      );
      // The relay also broadcasts room_extended to everyone (us included);
      // updating here just makes the countdown react instantly.
      roomMeta.expiresAt = Date.parse(res.expires_at);
      updateRoomTimer();
    } catch (err) {
      addMessage({ system: true, warning: true, text: 'Could not extend the room: ' + err.message });
    } finally {
      extendBtn.disabled = false;
    }
  }

  for (const btn of extendMenu.querySelectorAll('[data-minutes]')) {
    btn.addEventListener('click', () => extendRoom(parseInt(btn.dataset.minutes, 10)));
  }

  // ---- End room now (creator only) ----

  endRoomBtn.addEventListener('click', async () => {
    if (!roomMeta || !roomMeta.hostKey) return;
    if (!window.confirm('End this room for everyone now? This cannot be undone.')) return;
    endRoomBtn.disabled = true;
    try {
      await lobbyFetch(
        lobbyUrl(),
        '/rooms/' + encodeURIComponent(roomMeta.code),
        undefined,
        { 'X-Host-Key': roomMeta.hostKey },
        'DELETE'
      );
      // The relay broadcasts room_closed and drops everyone (us included);
      // no local teardown needed beyond the usual disconnect path.
      addMessage({ system: true, text: 'You ended the room.' });
    } catch (err) {
      addMessage({ system: true, warning: true, text: 'Could not end the room: ' + err.message });
    } finally {
      endRoomBtn.disabled = false;
    }
  });

  dmClearBtn.addEventListener('click', () => setDmTarget(null));

  disconnectBtn.addEventListener('click', teardown);
})();
