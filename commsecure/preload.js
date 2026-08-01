// Minimal bridge: the renderer can only load/save the persistent identity
// keypair (stored OS-keychain-encrypted by the main process). No other
// Node/Electron capability is exposed; session keys stay renderer-only.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('secureStore', {
  loadIdentity: () => ipcRenderer.invoke('identity:load'),
  saveIdentity: (identity) => ipcRenderer.invoke('identity:save', identity),
});
