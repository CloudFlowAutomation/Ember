const path = require('path');

// Gatekeeper shows downloaded builds as "damaged" unless the app is signed
// with a Developer ID certificate and notarized by Apple. Both kick in
// automatically when the credentials below are present in the environment;
// without them the build falls back to an ad-hoc signature (fine for local
// use, but downloads need `xattr -cr` — see README).
const osxSign = process.env.APPLE_SIGNING_IDENTITY
  ? { osxSign: { identity: process.env.APPLE_SIGNING_IDENTITY } }
  : {};

const osxNotarize =
  process.env.APPLE_ID && process.env.APPLE_PASSWORD && process.env.APPLE_TEAM_ID
    ? {
        osxNotarize: {
          appleId: process.env.APPLE_ID,
          appleIdPassword: process.env.APPLE_PASSWORD,
          teamId: process.env.APPLE_TEAM_ID,
        },
      }
    : {};

// Never publish an unsigned darwin build: Gatekeeper reports downloaded
// ad-hoc apps as "damaged", so a publish without full signing + notarization
// credentials only ships a broken artifact. Local `make` runs stay allowed
// either way, and this only applies to darwin — win32/linux publishes don't
// need Apple credentials.
const isPublishRun =
  process.env.npm_lifecycle_event === 'publish' ||
  process.argv.some((arg) => path.basename(arg).includes('publish'));
const platformArg = process.argv.find((arg) => arg.startsWith('--platform='));
const targetPlatform = platformArg ? platformArg.split('=')[1] : process.platform;
if (
  isPublishRun &&
  targetPlatform === 'darwin' &&
  !('osxSign' in osxSign && 'osxNotarize' in osxNotarize)
) {
  throw new Error(
    'Refusing to publish unsigned: set APPLE_SIGNING_IDENTITY, APPLE_ID, ' +
      'APPLE_PASSWORD, and APPLE_TEAM_ID so the build is signed and notarized ' +
      'before upload (see README).'
  );
}

module.exports = {
  packagerConfig: {
    appBundleId: 'io.darkmatterit.ember',
    icon: path.resolve(__dirname, 'assets', 'icon'),
    ...osxSign,
    ...osxNotarize,
  },
  makers: [
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin']
    },
    {
      name: '@electron-forge/maker-squirrel',
      platforms: ['win32'],
      config: {
        authors: 'Dark Matter IT',
        setupIcon: path.resolve(__dirname, 'assets', 'icon.ico'),
      }
    },
    {
      name: '@electron-forge/maker-deb',
      platforms: ['linux'],
      config: {
        options: {
          icon: path.resolve(__dirname, 'assets', 'icon.png'),
        }
      }
    }
  ],
  publishers: [
    {
      name: '@electron-forge/publisher-github',
      config: {
        repository: {
          owner: 'CivicPort',
          name: 'Ember'
        },
        prerelease: true,
        draft: false
      }
    }
  ]
}
