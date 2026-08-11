const { app, BrowserWindow, ipcMain, safeStorage, session } = require('electron');
const fs = require('fs');
const path = require('path');

const identityFile = () => path.join(app.getPath('userData'), 'identity.bin');

// The persistent Ed25519 identity key is the only secret that ever touches
// disk. It is encrypted with the OS keychain (safeStorage) when available.
// Session/encryption keys never leave renderer memory.
ipcMain.handle('identity:load', () => {
  try {
    const wrapper = JSON.parse(fs.readFileSync(identityFile(), 'utf8'));
    if (wrapper.enc) {
      if (!safeStorage.isEncryptionAvailable()) return null;
      return JSON.parse(safeStorage.decryptString(Buffer.from(wrapper.data, 'base64')));
    }
    return JSON.parse(Buffer.from(wrapper.data, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
});

ipcMain.handle('identity:save', (event, identity) => {
  const json = JSON.stringify(identity);
  const enc = safeStorage.isEncryptionAvailable();
  const data = enc
    ? safeStorage.encryptString(json).toString('base64')
    : Buffer.from(json, 'utf8').toString('base64');
  fs.writeFileSync(identityFile(), JSON.stringify({ v: 1, enc, data }), { mode: 0o600 });
  return enc;
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 800,
    minHeight: 520,
    title: 'Ember – Community Secure Chat',
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

// Calling needs the OS camera/mic; Electron denies media permission
// requests by default unless a handler explicitly allows them. The app
// window only ever requests 'media' (getUserMedia for calls), so nothing
// else needs approval here.
function allowMediaPermissions() {
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    callback(permission === 'media');
  });
}

app.whenReady().then(() => {
  // Packaged builds get the icon from the bundle; `npm start` runs the stock
  // Electron binary, so the Dock icon has to be set at runtime.
  if (process.platform === 'darwin' && app.dock && !app.isPackaged) {
    app.dock.setIcon(path.join(__dirname, 'assets', 'icon.png'));
  }
  allowMediaPermissions();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
