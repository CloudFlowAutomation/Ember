/* Ember renderer: connection lifecycle, roster, encrypted messaging.
   Session/encryption keys live only in this renderer's memory and are
   destroyed on disconnect. The persistent Ed25519 identity key (loaded via
   the preload bridge) signs each ephemeral session key so peers can detect
   a relay that swaps public keys (MITM). */
(function () {
  'use strict';

  const csc = window.EmberCrypto;
  const PINS_KEY = 'ember-identity-pins';

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
  const settingsModal = document.getElementById('settings-modal');
  const settingsCloseBtn = document.getElementById('settings-close');
  const serverUrlSetting = document.getElementById('server-url-setting');
  const lobbyUrlSetting = document.getElementById('lobby-url-setting');
  const lobbyApiKeySetting = document.getElementById('lobby-api-key-setting');
  const iceServerSetting = document.getElementById('ice-server-setting');
  const iceUsernameSetting = document.getElementById('ice-username-setting');
  const iceCredentialSetting = document.getElementById('ice-credential-setting');
  const modeDirectBtn = document.getElementById('mode-direct');
  const modeRoomBtn = document.getElementById('mode-room');
  const roomFields = document.getElementById('room-fields');
  const joinCodeInput = document.getElementById('join-code');
  const roomNameInput = document.getElementById('room-name');
  const roomDurationInput = document.getElementById('room-duration');
  const roomAllowExtendInput = document.getElementById('room-allow-extend');
  const createRoomBtn = document.getElementById('create-room-btn');
  const roomInfoEl = document.getElementById('room-info');
  const backToServerBtn = document.getElementById('back-to-server-btn');
  const switchRoomBtn = document.getElementById('switch-room-btn');
  const switchRoomRecentEl = document.getElementById('switch-room-recent');
  const switchRoomRecentListEl = document.getElementById('switch-room-recent-list');
  const switchRoomModal = document.getElementById('switch-room-modal');
  const switchRoomCloseBtn = document.getElementById('switch-room-close');
  const switchRoomForm = document.getElementById('switch-room-form');
  const switchModeDirectBtn = document.getElementById('switch-mode-direct');
  const switchModeRoomBtn = document.getElementById('switch-mode-room');
  const switchRoomFieldsEl = document.getElementById('switch-room-fields');
  const switchJoinCodeInput = document.getElementById('switch-join-code');
  const switchRoomNameInput = document.getElementById('switch-room-name');
  const switchRoomDurationInput = document.getElementById('switch-room-duration');
  const switchRoomAllowExtendInput = document.getElementById('switch-room-allow-extend');
  const switchCreateRoomBtn = document.getElementById('switch-create-room-btn');
  const switchRoomInfoEl = document.getElementById('switch-room-info');
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
  const incomingCallBanner = document.getElementById('incoming-call-banner');
  const incomingCallNameEl = document.getElementById('incoming-call-name');
  const incomingCallAcceptBtn = document.getElementById('incoming-call-accept');
  const incomingCallDeclineBtn = document.getElementById('incoming-call-decline');
  const callOverlay = document.getElementById('call-overlay');
  const callRemoteVideo = document.getElementById('call-remote-video');
  const callLocalVideo = document.getElementById('call-local-video');
  const callStatusEl = document.getElementById('call-status');
  const callToggleMicBtn = document.getElementById('call-toggle-mic');
  const callToggleCameraBtn = document.getElementById('call-toggle-camera');
  const callHangupBtn = document.getElementById('call-hangup');

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

        const actions = document.createElement('div');
        actions.className = 'peer-actions';
        const callBtn = document.createElement('button');
        callBtn.type = 'button';
        callBtn.className = 'roster-call-btn';
        callBtn.textContent = '📞 Call';
        callBtn.disabled = !!activeCall || !!pendingIncomingCall;
        callBtn.title = 'Start an encrypted call with ' + peer.username;
        callBtn.addEventListener('click', (e) => {
          e.stopPropagation(); // don't also toggle the DM target
          startCall(sid);
        });
        actions.appendChild(callBtn);
        li.appendChild(actions);
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
        if (pendingIncomingCall && pendingIncomingCall.sid === sid) {
          pendingIncomingCall = null;
          incomingCallBanner.classList.add('hidden');
        }
        if (activeCall && activeCall.peerSid === sid) {
          endCall({ notifyPeer: false, message: peer.username + ' left the room — call ended.' });
        }
        addMessage({ system: true, text: `${peer.username} left the room` });
      }
    }
    renderRoster();
  }

  // Tears down the live connection (socket, session, roster, message state)
  // without touching which screen is visible — used both by a full logout
  // and by an in-place room switch, which immediately opens a new
  // connection afterwards instead of returning to the connect screen.
  function resetConnectionState() {
    endCallForConnectionReset();
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
    dmTarget = null;
    dmIndicator.classList.add('hidden');
    stopRoomTimer();
    roomMeta = null;
    messagesEl.textContent = '';
    rosterEl.textContent = '';
  }

  function teardown() {
    resetConnectionState();
    chatScreen.classList.add('hidden');
    connectScreen.classList.remove('hidden');
  }

  // ---- Settings (persisted) ----

  // Both endpoints are user-configurable in the Settings panel and persist
  // across sessions; blank falls back to the default. The lobby is the
  // control plane that provisions each private room's MicroVM.
  const DEFAULT_SERVER_URL = 'http://localhost:8000';
  const DEFAULT_LOBBY_URL = 'http://localhost:8100';
  const SETTINGS_KEY = 'ember-settings';

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

  function lobbyApiKey() {
    return (loadSettings().lobbyApiKey || '').trim();
  }

  settingsToggleBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    serverUrlSetting.focus();
  });

  settingsCloseBtn.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
  });

  settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) settingsModal.classList.add('hidden');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !settingsModal.classList.contains('hidden')) {
      settingsModal.classList.add('hidden');
    }
    if (e.key === 'Escape' && !switchRoomModal.classList.contains('hidden')) {
      closeSwitchRoomModal();
    }
  });

  serverUrlSetting.value = loadSettings().serverUrl || '';
  serverUrlSetting.addEventListener('change', () => {
    saveSettings({ serverUrl: serverUrlSetting.value.trim() });
  });

  lobbyUrlSetting.value = loadSettings().lobbyUrl || '';
  lobbyUrlSetting.addEventListener('change', () => {
    saveSettings({ lobbyUrl: lobbyUrlSetting.value.trim() });
  });

  lobbyApiKeySetting.value = loadSettings().lobbyApiKey || '';
  lobbyApiKeySetting.addEventListener('change', () => {
    saveSettings({ lobbyApiKey: lobbyApiKeySetting.value.trim() });
  });

  iceServerSetting.value = loadSettings().iceServer || '';
  iceServerSetting.addEventListener('change', () => {
    saveSettings({ iceServer: iceServerSetting.value.trim() });
  });

  iceUsernameSetting.value = loadSettings().iceUsername || '';
  iceUsernameSetting.addEventListener('change', () => {
    saveSettings({ iceUsername: iceUsernameSetting.value.trim() });
  });

  iceCredentialSetting.value = loadSettings().iceCredential || '';
  iceCredentialSetting.addEventListener('change', () => {
    saveSettings({ iceCredential: iceCredentialSetting.value.trim() });
  });

  // Builds the RTCPeerConnection iceServers list from settings. Blank
  // config means host-only candidates — calls still connect on the same
  // LAN/simple NAT, just without help crossing a stricter one.
  function iceServers() {
    const url = (loadSettings().iceServer || '').trim();
    if (!url) return [];
    const entry = { urls: url };
    const username = (loadSettings().iceUsername || '').trim();
    const credential = (loadSettings().iceCredential || '').trim();
    if (username) entry.username = username;
    if (credential) entry.credential = credential;
    return [entry];
  }

  // ---- Host keys (persisted so the creator can still extend after an
  // app restart). Entries are pruned at the 8 h platform lifetime cap. ----

  const HOSTKEYS_KEY = 'ember-host-keys';

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

  // ---- Recent destinations (so switching rooms doesn't lose the trail) ----

  const ROOM_HISTORY_KEY = 'ember-room-history';
  const ROOM_HISTORY_MAX = 6;

  function historyKey(entry) {
    return entry.kind === 'room' ? 'room:' + entry.code : 'direct';
  }

  function loadRoomHistory() {
    let list;
    try {
      list = JSON.parse(localStorage.getItem(ROOM_HISTORY_KEY)) || [];
    } catch (e) {
      list = [];
    }
    // Rooms drop off the trail once they've expired; the shared server never
    // expires so it's always eligible to switch back to.
    return list.filter((e) => e.kind === 'direct' || e.expiresAt > Date.now());
  }

  // Called on every successful connection so wherever we just left stays
  // reachable from the switch-room modal. Most-recent-first, deduped by
  // destination, capped so the list can't grow without bound.
  function recordRoomHistory(entry) {
    const key = historyKey(entry);
    const list = loadRoomHistory().filter((e) => historyKey(e) !== key);
    list.unshift(entry);
    localStorage.setItem(ROOM_HISTORY_KEY, JSON.stringify(list.slice(0, ROOM_HISTORY_MAX)));
  }

  function renderRecentRooms() {
    const current = roomMeta ? historyKey({ kind: 'room', code: roomMeta.code }) : 'direct';
    const entries = loadRoomHistory().filter((e) => historyKey(e) !== current);
    switchRoomRecentListEl.textContent = '';
    switchRoomRecentEl.classList.toggle('hidden', entries.length === 0);
    for (const entry of entries) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'recent-room-btn';
      const name = document.createElement('span');
      name.className = 'recent-room-name';
      name.textContent = entry.kind === 'direct' ? 'Shared server' : entry.name;
      btn.appendChild(name);
      if (entry.kind === 'room') {
        const meta = document.createElement('span');
        meta.className = 'recent-room-meta';
        meta.textContent = fmtRemaining(entry.expiresAt - Date.now());
        btn.appendChild(meta);
      }
      btn.addEventListener('click', () => switchToRecent(entry));
      li.appendChild(btn);
      switchRoomRecentListEl.appendChild(li);
    }
  }

  async function switchToRecent(entry) {
    setSwitchRoomInfo('');
    try {
      await beginConnection(entry.kind, entry.kind === 'room' ? entry.code : undefined, setSwitchRoomInfo);
      closeSwitchRoomModal();
    } catch (err) {
      setSwitchRoomInfo('Could not switch back: ' + err.message);
    }
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
    const apiKey = lobbyApiKey();
    let res;
    try {
      res = await fetch(base.replace(/\/+$/, '') + path, {
        method: method || (body === undefined ? 'GET' : 'POST'),
        headers: Object.assign(
          { 'Content-Type': 'application/json' },
          apiKey ? { 'X-Api-Key': apiKey } : {},
          headers || {}
        ),
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

  // Shared by both the initial connect form and the switch-room modal, so
  // creating a room works identically from either place.
  async function createRoom({ durationInput, allowExtendInput, nameInput, joinCodeInputEl, report, button }) {
    const minutes = parseInt(durationInput.value, 10);
    if (!minutes) return;
    button.disabled = true;
    report('Creating room…');
    try {
      const allowExtend = allowExtendInput.checked;
      const name = nameInput.value.trim();
      const room = await lobbyFetch(lobbyUrl(), '/rooms', {
        duration_minutes: minutes,
        allow_extend: allowExtend,
        name: name || undefined,
      });
      // Keeping the host key marks us as this room's creator: it unlocks
      // the Extend control in the chat header.
      saveHostKey(room.join_code, room.host_key);
      joinCodeInputEl.value = room.join_code;
      report(
        'Room created — share code ' + room.join_code +
        '. It expires at ' + new Date(room.expires_at).toLocaleTimeString() +
        ' and closes early after 10 minutes without messages.' +
        (allowExtend
          ? ' As its creator you can extend it from inside the room.'
          : ' It cannot be extended.')
      );
    } catch (err) {
      report('Could not create room: ' + err.message);
    } finally {
      button.disabled = false;
    }
  }

  createRoomBtn.addEventListener('click', () => createRoom({
    durationInput: roomDurationInput,
    allowExtendInput: roomAllowExtendInput,
    nameInput: roomNameInput,
    joinCodeInputEl: joinCodeInput,
    report: setRoomInfo,
    button: createRoomBtn,
  }));

  switchCreateRoomBtn.addEventListener('click', () => createRoom({
    durationInput: switchRoomDurationInput,
    allowExtendInput: switchRoomAllowExtendInput,
    nameInput: switchRoomNameInput,
    joinCodeInputEl: switchJoinCodeInput,
    report: setSwitchRoomInfo,
    button: switchCreateRoomBtn,
  }));

  // Exchange a join code for the room's endpoint URL and a platform auth
  // token that expires with the room; wait out the VM's cold start. `report`
  // routes progress text to whichever info line is visible (connect screen
  // vs. the switch-room modal).
  async function joinPrivateRoom(lobby, code, report) {
    report('Looking up room…');
    const join = await lobbyFetch(lobby, '/rooms/join', { code });
    let state = join.state;
    const deadline = Date.now() + 90000;
    while (state === 'PENDING' && Date.now() < deadline) {
      report('Room is starting…');
      await sleep(2000);
      const status = await lobbyFetch(lobby, '/rooms/' + encodeURIComponent(code.replace(/[^A-Za-z0-9]/g, '')));
      state = status.state;
    }
    if (state === 'PENDING') throw new Error('The room did not start in time. Try again.');
    report('Joining "' + join.name + '" — room expires at ' + new Date(join.expires_at).toLocaleTimeString());
    return join;
  }

  // Resolves the target first (for a room, that means confirming the join
  // code works before giving up the current connection), then tears down
  // whatever is currently connected and opens the new one. Used for the
  // initial connect AND for switching rooms without a full logout — in the
  // latter case `resetConnectionState` just has a live connection to drop.
  async function beginConnection(kind, code, report) {
    if (kind === 'direct') {
      resetConnectionState();
      roomMeta = null;
      openSocket(serverUrl(), {});
      return;
    }
    const join = await joinPrivateRoom(lobbyUrl(), code, report);
    resetConnectionState();
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
  }

  connectForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!identity || socket) return;
    connectError.classList.add('hidden');
    username = usernameInput.value.trim();
    if (!username) return;

    if (mode === 'direct') {
      try {
        await beginConnection('direct');
      } catch (err) {
        showError(err.message);
      }
      return;
    }

    const code = joinCodeInput.value.trim();
    if (!code) {
      setRoomInfo('Enter a join code, or create a room first.');
      return;
    }
    connectButton.disabled = true;
    try {
      await beginConnection('room', code, setRoomInfo);
    } catch (err) {
      showError(err.message);
    } finally {
      connectButton.disabled = false;
    }
  });

  // ---- Switch room (from inside the chat screen, no logout needed) ----

  let switchMode = 'direct';

  function setSwitchMode(next) {
    switchMode = next;
    switchModeDirectBtn.classList.toggle('active', next === 'direct');
    switchModeRoomBtn.classList.toggle('active', next === 'room');
    switchRoomFieldsEl.classList.toggle('hidden', next !== 'room');
  }

  switchModeDirectBtn.addEventListener('click', () => setSwitchMode('direct'));
  switchModeRoomBtn.addEventListener('click', () => setSwitchMode('room'));

  function setSwitchRoomInfo(text) {
    switchRoomInfoEl.textContent = text;
    switchRoomInfoEl.classList.toggle('hidden', !text);
  }

  function openSwitchRoomModal() {
    setSwitchMode('direct');
    switchJoinCodeInput.value = '';
    setSwitchRoomInfo('');
    renderRecentRooms();
    switchRoomModal.classList.remove('hidden');
  }

  function closeSwitchRoomModal() {
    switchRoomModal.classList.add('hidden');
  }

  switchRoomBtn.addEventListener('click', openSwitchRoomModal);
  switchRoomCloseBtn.addEventListener('click', closeSwitchRoomModal);
  switchRoomModal.addEventListener('click', (e) => {
    if (e.target === switchRoomModal) closeSwitchRoomModal();
  });

  // Jumps straight back to the shared server without opening the modal —
  // the common case of "I'm in a private room, take me back to the main
  // server" shouldn't need the mode toggle at all. Only shown while a
  // private room is active (see openSocket).
  async function backToSharedServer() {
    if (!identity || !socket) return;
    backToServerBtn.disabled = true;
    try {
      await beginConnection('direct');
    } catch (err) {
      addMessage({ system: true, warning: true, text: 'Could not switch back to the shared server: ' + err.message });
    } finally {
      backToServerBtn.disabled = false;
    }
  }

  backToServerBtn.addEventListener('click', backToSharedServer);

  switchRoomForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!identity || !socket) return;
    const submitBtn = switchRoomForm.querySelector('button[type="submit"]');
    if (switchMode === 'direct') {
      submitBtn.disabled = true;
      try {
        await beginConnection('direct');
        closeSwitchRoomModal();
      } catch (err) {
        setSwitchRoomInfo('Could not connect: ' + err.message);
      } finally {
        submitBtn.disabled = false;
      }
      return;
    }
    const code = switchJoinCodeInput.value.trim();
    if (!code) {
      setSwitchRoomInfo('Enter a join code, or create a room first.');
      return;
    }
    submitBtn.disabled = true;
    try {
      await beginConnection('room', code, setSwitchRoomInfo);
      closeSwitchRoomModal();
    } catch (err) {
      setSwitchRoomInfo(err.message);
    } finally {
      submitBtn.disabled = false;
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
        recordRoomHistory(
          roomMeta
            ? { kind: 'room', code: roomMeta.code, name: roomMeta.name, expiresAt: roomMeta.expiresAt }
            : { kind: 'direct' }
        );
        selfNameEl.textContent = username + ' (you)';
        selfFingerprintEl.textContent = csc.fingerprint(csc.publicKeyB64(identity));
        chatTitleEl.textContent = roomMeta ? roomMeta.name : 'Community room';
        backToServerBtn.classList.toggle('hidden', !roomMeta);
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
        } else if (typeof envelope.t === 'string' && envelope.t.startsWith('call-')) {
          await handleCallEnvelope(envelope, msg.from);
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
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dmTarget) setDmTarget(null);
  });

  // ---- Encrypted calling ----
  // WebRTC offer/answer/ICE ride the same per-peer authenticated E2E
  // channel as DMs (sendEncrypted with onlySid) instead of a separate
  // signaling path, so call setup gets the same identity-signed protection
  // against a MITM relay as everything else. Media itself is additionally
  // protected by WebRTC's mandatory DTLS-SRTP. One call at a time.

  let activeCall = null; // { peerSid, peerName, pc, localStream, direction, established, micMuted, cameraOff }
  let pendingIncomingCall = null; // { sid, name, offer, candidates: [] } — ringing, not yet accepted

  function sendCallEnvelope(sid, envelope) {
    sendEncrypted(ENVELOPE_PREFIX + JSON.stringify(envelope), sid);
  }

  function setCallStatus(text) {
    callStatusEl.textContent = text;
  }

  function newPeerConnection() {
    const pc = new RTCPeerConnection({ iceServers: iceServers() });
    pc.onicecandidate = (e) => {
      if (!e.candidate || !activeCall) return;
      sendCallEnvelope(activeCall.peerSid, { t: 'call-ice', candidate: e.candidate.toJSON() });
    };
    pc.ontrack = (e) => {
      callRemoteVideo.srcObject = e.streams[0] || null;
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') setCallStatus('');
      if (['failed', 'disconnected', 'closed'].includes(pc.connectionState) && activeCall && activeCall.pc === pc) {
        endCall({ notifyPeer: false, message: 'Call disconnected.' });
      }
    };
    return pc;
  }

  async function getCallMedia() {
    return navigator.mediaDevices.getUserMedia({
      audio: true,
      video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
    });
  }

  // Congestion control starts conservative and ramps up slowly, especially
  // over the TURN relay hop. Raise the ceiling so a good connection can
  // actually reach 720p-ish quality instead of settling for its default cap.
  async function raiseVideoBitrate(pc) {
    const sender = pc.getSenders().find((s) => s.track && s.track.kind === 'video');
    if (!sender) return;
    const params = sender.getParameters();
    if (!params.encodings || !params.encodings.length) params.encodings = [{}];
    params.encodings[0].maxBitrate = 2500000;
    try {
      await sender.setParameters(params);
    } catch (e) {
      // Not fatal — call still works at the default bitrate cap.
    }
  }

  function showCallOverlay() {
    incomingCallBanner.classList.add('hidden');
    callOverlay.classList.remove('hidden');
  }

  function hideCallOverlay() {
    callOverlay.classList.add('hidden');
    callRemoteVideo.srcObject = null;
    callLocalVideo.srcObject = null;
    callToggleMicBtn.classList.remove('muted');
    callToggleCameraBtn.classList.remove('muted');
  }

  async function startCall(sid) {
    const peer = peers.get(sid);
    if (activeCall || pendingIncomingCall || !peer || !peer.state) return;
    let localStream;
    try {
      localStream = await getCallMedia();
    } catch (e) {
      addMessage({ system: true, warning: true, text: 'Could not access camera/microphone: ' + e.message });
      return;
    }
    const pc = newPeerConnection();
    localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));
    await raiseVideoBitrate(pc);
    activeCall = {
      peerSid: sid,
      peerName: peer.username,
      pc,
      localStream,
      direction: 'outgoing',
      established: false,
      micMuted: false,
      cameraOff: false,
    };
    callLocalVideo.srcObject = localStream;
    setCallStatus('Calling ' + peer.username + '…');
    showCallOverlay();
    renderRoster();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendCallEnvelope(sid, { t: 'call-offer', sdp: offer.sdp });
  }

  async function acceptIncomingCall() {
    if (!pendingIncomingCall) return;
    const { sid, name, offer, candidates } = pendingIncomingCall;
    pendingIncomingCall = null;
    let localStream;
    try {
      localStream = await getCallMedia();
    } catch (e) {
      addMessage({ system: true, warning: true, text: 'Could not access camera/microphone: ' + e.message });
      sendCallEnvelope(sid, { t: 'call-end' });
      incomingCallBanner.classList.add('hidden');
      return;
    }
    const pc = newPeerConnection();
    localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));
    await raiseVideoBitrate(pc);
    activeCall = {
      peerSid: sid,
      peerName: name,
      pc,
      localStream,
      direction: 'incoming',
      established: true,
      micMuted: false,
      cameraOff: false,
    };
    callLocalVideo.srcObject = localStream;
    setCallStatus('Connecting…');
    showCallOverlay();
    renderRoster();
    await pc.setRemoteDescription({ type: 'offer', sdp: offer });
    for (const candidate of candidates) {
      try {
        await pc.addIceCandidate(candidate);
      } catch (e) {
        // A stale/invalid candidate here just means one fewer ICE path.
      }
    }
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendCallEnvelope(sid, { t: 'call-answer', sdp: answer.sdp });
  }

  function declineIncomingCall() {
    if (!pendingIncomingCall) return;
    sendCallEnvelope(pendingIncomingCall.sid, { t: 'call-end' });
    pendingIncomingCall = null;
    incomingCallBanner.classList.add('hidden');
    renderRoster();
  }

  function endCall({ notifyPeer = true, message = 'Call ended.' } = {}) {
    if (!activeCall) return;
    const { peerSid, pc, localStream } = activeCall;
    if (notifyPeer) sendCallEnvelope(peerSid, { t: 'call-end' });
    pc.onicecandidate = null;
    pc.ontrack = null;
    pc.onconnectionstatechange = null;
    pc.close();
    localStream.getTracks().forEach((track) => track.stop());
    activeCall = null;
    hideCallOverlay();
    renderRoster();
    if (message) addMessage({ system: true, text: message });
  }

  // Called when the current connection is torn down (disconnect, room
  // switch) — nothing on the other end will be listening for signaling
  // envelopes afterward, so there's no peer left to notify.
  function endCallForConnectionReset() {
    if (pendingIncomingCall) {
      pendingIncomingCall = null;
      incomingCallBanner.classList.add('hidden');
    }
    if (activeCall) endCall({ notifyPeer: false, message: null });
  }

  async function handleCallEnvelope(envelope, from) {
    const peer = peers.get(from);
    if (envelope.t === 'call-offer' && typeof envelope.sdp === 'string') {
      if (activeCall || pendingIncomingCall || !peer) {
        sendCallEnvelope(from, { t: 'call-busy' });
        return;
      }
      pendingIncomingCall = { sid: from, name: peer.username, offer: envelope.sdp, candidates: [] };
      incomingCallNameEl.textContent = peer.username;
      incomingCallBanner.classList.remove('hidden');
      renderRoster();
    } else if (envelope.t === 'call-answer' && typeof envelope.sdp === 'string') {
      if (!activeCall || activeCall.peerSid !== from || activeCall.direction !== 'outgoing') return;
      activeCall.established = true;
      await activeCall.pc.setRemoteDescription({ type: 'answer', sdp: envelope.sdp });
    } else if (envelope.t === 'call-ice' && envelope.candidate) {
      if (activeCall && activeCall.peerSid === from) {
        try {
          await activeCall.pc.addIceCandidate(envelope.candidate);
        } catch (e) {
          // Ignore — a dropped candidate just means one fewer ICE path.
        }
      } else if (pendingIncomingCall && pendingIncomingCall.sid === from) {
        pendingIncomingCall.candidates.push(envelope.candidate);
      }
    } else if (envelope.t === 'call-end') {
      if (pendingIncomingCall && pendingIncomingCall.sid === from) {
        pendingIncomingCall = null;
        incomingCallBanner.classList.add('hidden');
        renderRoster();
      } else if (activeCall && activeCall.peerSid === from) {
        endCall({ notifyPeer: false, message: (peer ? peer.username : 'The other person') + ' ended the call.' });
      }
    } else if (envelope.t === 'call-busy') {
      if (activeCall && activeCall.peerSid === from && !activeCall.established) {
        endCall({ notifyPeer: false, message: (peer ? peer.username : 'They') + ' are on another call.' });
      }
    }
  }

  callHangupBtn.addEventListener('click', () => endCall());
  incomingCallAcceptBtn.addEventListener('click', acceptIncomingCall);
  incomingCallDeclineBtn.addEventListener('click', declineIncomingCall);

  callToggleMicBtn.addEventListener('click', () => {
    if (!activeCall) return;
    activeCall.micMuted = !activeCall.micMuted;
    activeCall.localStream.getAudioTracks().forEach((t) => (t.enabled = !activeCall.micMuted));
    callToggleMicBtn.classList.toggle('muted', activeCall.micMuted);
  });

  callToggleCameraBtn.addEventListener('click', () => {
    if (!activeCall) return;
    activeCall.cameraOff = !activeCall.cameraOff;
    activeCall.localStream.getVideoTracks().forEach((t) => (t.enabled = !activeCall.cameraOff));
    callToggleCameraBtn.classList.toggle('muted', activeCall.cameraOff);
  });

  disconnectBtn.addEventListener('click', teardown);
})();
