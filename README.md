![Logo](admin/mihome-cloud.png)

# ioBroker.mihome-cloud

[![NPM version](https://img.shields.io/npm/v/iobroker.mihome-cloud.svg)](https://www.npmjs.com/package/iobroker.mihome-cloud)
[![Downloads](https://img.shields.io/npm/dm/iobroker.mihome-cloud.svg)](https://www.npmjs.com/package/iobroker.mihome-cloud)
![Number of Installations](https://iobroker.live/badges/mihome-cloud-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/mihome-cloud-stable.svg)

[![NPM](https://nodei.co/npm/iobroker.mihome-cloud.png?downloads=true)](https://nodei.co/npm/iobroker.mihome-cloud/)

**Tests:** ![Test and Release](https://github.com/TA2k/ioBroker.mihome-cloud/workflows/Test%20and%20Release/badge.svg)

## mihome-cloud adapter for ioBroker

Adapter for all Mi Home Cloud devices. Connects to the Xiaomi Cloud API and provides status, control and scene execution for all devices registered in your Mi Home account.

**This adapter uses Sentry libraries to automatically report exceptions and code errors to the developers.** For more details and for information how to disable the error reporting see [Sentry-Plugin Documentation](https://github.com/ioBroker/plugin-sentry#plugin-sentry)! Sentry reporting is used starting with js-controller 5.0.

## Requirements

- Node.js >= 20
- js-controller >= 6.0.11
- Admin >= 7.6.20

## Configuration

In the adapter settings you can configure:

| Setting             | Description                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| **Region**          | Select the Xiaomi Cloud region matching your Mi Home app (Germany, China, Russia, Taiwan, Singapore, USA) |
| **Update interval** | Polling interval in minutes for device status updates via the Xiaomi Cloud API (minimum 1 minute in Admin UI) |
| **Login cooldown**  | Minimum time between automatic login attempts (login URL creation) after an expired or failed session. `0` disables automatic login attempts. |

## Login

The adapter uses a **URL-based login** (no username/password needed in the adapter settings).

1. Configure **Region**, **Update interval** and (optionally) **Login cooldown** in the adapter settings and save.
2. Start the adapter.
3. The adapter creates a **login URL** and exposes it in two places:
   - as a warning in the adapter log
   - as state `mihome-cloud.0.auth.loginUrl`
4. Open the URL in your browser and sign in with your Xiaomi account.
5. The adapter detects the successful login automatically and connects.

When the session expires server-side, the adapter clears the invalid session and switches to re-authentication state (`mihome-cloud.0.auth.status = reauth_required`).

- If **Login cooldown > 0**, automatic login attempts are started.
- If **Login cooldown = 0**, automatic login attempts are disabled by design.

The session is persisted in `auth.session` and can be reused after adapter restarts when still valid.

## Object tree

After startup and login, the adapter creates the following object structure:

### `mihome-cloud.0.info.connection`

Connection indicator (`true`/`false`) for the Xiaomi Cloud session.

### `mihome-cloud.0.auth.*`

Authentication runtime and session states:

- `auth.status` - current authentication state (for example `connected`, `qr_login_pending`, `reauth_required`, `cooldown_wait`)
- `auth.loginUrl` - current Xiaomi login URL used for browser login
- `auth.session` - persisted cookie/session JSON for session restore

Per device, the adapter creates:

### `mihome-cloud.0.<device-id>.general`

General device information (model, name, firmware version, etc.).

### `mihome-cloud.0.<device-id>.status`

Read-only states from MIoT specification properties and events. These are polled at the configured update interval.

### `mihome-cloud.0.<device-id>.remote`

Writable MIoT specification properties and actions.

- Writable properties are sent via MIoT `prop/set`
- Actions are sent via MIoT `action`
- Actions with input arguments expect JSON input in the state value

After commands, the adapter performs an automatic status refresh.

### `mihome-cloud.0.<device-id>.custom`

Model-specific states from internal `configDes` mappings (for example vacuum metrics such as `clean_area`, `clean_time`, `battery`).

### `mihome-cloud.0.<device-id>.remotePlugins`

Additional writable commands extracted from Xiaomi plugin bundles (best-effort, depends on plugin/model).

### `mihome-cloud.0.scenes`

Smart scenes / automations from your Mi Home account. Set a scene state to `true` to execute it.

## Example: Robot vacuum room cleaning

1. Find room IDs:

   `mihome-cloud.0.<id>.remote.get-map-room-list` – requires `[cur-map-id]` as input.

   You can get the current map ID from `mihome-cloud.0.<id>.status.cur-map-id`, or query the map list via:

   `mihome-cloud.0.<id>.remote.get-map-list` (no input needed) → result appears under `mihome-cloud.0.<id>.status.map-list`

2. Set the map ID and query rooms:

   `mihome-cloud.0.<id>.remote.get-map-room-list` with input `[<map-id>]`

   → Result: `mihome-cloud.0.<id>.status.room-id-name-list`: `[{"name":"room1","id":10}]`

3. Start room cleaning:

   `mihome-cloud.0.<id>.remote.start-room-sweep` with format `["10", "11", "12", "13"]`

   or

   `mihome-cloud.0.<id>.remote.set-room-clean` with format `["10",0,1]`

## Troubleshooting

- **"DB closed" errors**: Harmless – occurs when the adapter is stopping while a request is still pending. These are suppressed automatically.
- **"ECONNRESET" errors**: Temporary network interruptions to the Xiaomi Cloud. The adapter retries automatically at the next polling interval.
- **"-106 device network unreachable"**: The device (e.g., a vacuum cleaner) is currently offline, disconnected from Wi-Fi, or powered off. The adapter will log this as debug and keep trying.
- **401/400 authentication errors**: The adapter clears the invalid session and enters re-authentication mode. A new login URL is provided via log warning and `auth.loginUrl` if automatic login attempts are enabled.
- **No new login URL after session expiry**: Check **Login cooldown**. If set to `0`, automatic login attempts (and automatic login URL creation) are disabled.
- **No properties for device**: Some pure Zigbee/Bluetooth sensor devices (e.g. `lumi.sensor_switch.v2`) do not expose their status via the Cloud API. Consider using a local Zigbee adapter instead.

## Discussion and questions

<https://forum.iobroker.net/topic/59636/test-adapter-mihome-cloud>

## Changelog
### **WORK IN PROGRESS**
- (lubepi) **ENHANCED**: Added configurable login cooldown with optional disable mode (`0`) for automatic login attempts
- (lubepi) **ENHANCED**: Exposed Xiaomi login URL in `auth.loginUrl` for automation and easier re-authentication handling
- (lubepi) **ENHANCED**: Updated README sections for configuration, login flow, object tree, troubleshooting, and requirements alignment

### 1.0.5 (2026-04-01)
- (lubepi) improve 401 authentication error handling and session reset
- (lubepi) validate and limit user configurable update interval
- (lubepi) update dependencies to address vulnerabilities

### 1.0.4 (2026-03-14)
- (lubepi) Maintenance update: Consolidated changelog and fixed repository metadata for better standards compliance

### 1.0.3 (2026-03-14)
- (lubepi) Improved error handling for network interruptions
- (lubepi) Migration to external i18n files and Node.js 20+ requirement
- (lubepi) Updated dependencies and fixed known vulnerabilities
- (lubepi) Added missing translations (uk, ru, pt, nl, fr, it, es, pl, zh-cn)
- (lubepi) Migration to ESLint flat config and release-script support

### 0.2.2

- (lubepi) Minor improvements with device handling

### 0.2.1

- (lubepi) Fix login. Check Log after starting Adapter

### 0.2.0

- (lubepi) Fix login

### 0.0.5

- (TA2k) Bugfixes

### 0.0.4

- (TA2k) initial release

## License

MIT License

Copyright (c) 2023-2026 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
