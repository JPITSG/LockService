# LockService

A lightweight Windows service that locks workstations and turns off monitors, controllable via HTTP API and Win+L hotkey interception.

## What It Does

LockService runs as a Windows service and provides two ways to lock the screen and power off monitors:

- **HTTP API** — Send a GET request to `http://localhost:8888/lock` to lock all active sessions and turn off monitors. Useful for automation, scripts, or triggering a lock from another machine on the network.
- **Win+L Interception** — The service attaches a keyboard hook helper into each active user session. When Win+L is pressed, it locks the workstation and immediately turns off monitors (the default Windows behavior only locks without powering off displays).

The service automatically tracks user sessions — attaching helpers when users log in and cleaning them up when sessions end. Up to 32 concurrent sessions are supported.

## Installation

### Requirements

- Windows 10/11 (x86_64)
- Administrator privileges
- Microsoft Edge WebView2 Runtime (pre-installed on most Windows 10/11 systems)

### Using the GUI

Double-click `LockService.exe` (as Administrator). A configuration window will appear with:

- **Service Status** badge — green when running, red when stopped, outline when not installed.
- **Enable HTTP Service** / **Turn off monitor(s) on WIN+L** switches to independently toggle the HTTP server and the monitor-off behavior (both enabled by default).
- **Bind IP / Bind Port** fields to configure what address and port the HTTP server listens on (defaults: `0.0.0.0` / `8888`). Changes are saved to the registry. If the service is already running, saving will automatically restart it.
- **Save** button — only enabled when settings have been changed.
- **Install**, **Uninstall**, **Restart**, **Start**, and **Stop** buttons (disabled based on current service state).

If launched without admin privileges, a warning dialog will prompt you to re-run as Administrator.

The GUI is built with React + shadcn/ui rendered inside an embedded WebView2 control. All frontend assets and the WebView2Loader.dll are bundled inside the executable — no external files are required.

### Using the Command Line

```
LockService.exe install
LockService.exe uninstall
```

Once installed, the service starts automatically on boot. You can also manage it through `services.msc` or `sc`:

```
sc start LockService
sc stop LockService
sc query LockService
```

## Configuration

Settings are stored in the registry at `HKLM\SOFTWARE\JPIT\LockService`:

| Value             | Type      | Default   | Description                                |
|-------------------|-----------|-----------|--------------------------------------------|
| `BindIP`          | REG_SZ    | `0.0.0.0` | IP address the HTTP server binds to        |
| `BindPort`        | REG_DWORD | `8888`    | Port the HTTP server listens on (1–65535)  |
| `EnableHTTP`      | REG_DWORD | `1`       | Enable (1) or disable (0) the HTTP server  |
| `EnableMonitorOff`| REG_DWORD | `1`       | Enable (1) or disable (0) monitor-off on WIN+L |

These can be edited through the GUI or directly in the registry for headless/scripted setups. Changes require a service restart to take effect.

## HTTP API

With the service running, a single endpoint is available (port is configurable, default `8888`):

```
GET http://localhost:8888/lock
```

Response (200):
```json
{"status":"ok","message":"Sessions locked"}
```

Unrecognized endpoints return 404:
```json
{"status":"error","message":"Endpoint not found"}
```

Example usage:
```bash
curl http://localhost:8888/lock
curl http://192.168.1.100:8888/lock
```

## How It Works

### Architecture

```
LockService.exe (service)
├── Session monitor thread (polls every 10s)
│   └── Spawns keyboard hook helpers per active user session
├── HTTP server thread (listens on configured IP:port)
└── Keyboard hook helper (per session)
    ├── RawInput API (primary — works with elevated apps)
    ├── RegisterHotKey (backup)
    └── Low-level keyboard hook WH_KEYBOARD_LL (tertiary)
```

The service runs as LOCAL SYSTEM. For each active user session, it spawns a helper process (`--keyboard-hook` flag) under that user's token with elevated privileges when available. Helpers use a single-instance mutex to prevent duplicates within a session.

When Win+L is detected, the helper verifies no other modifiers (Ctrl, Alt, Shift) are held, logs the event to the Windows Event Viewer, and turns off monitors after a 500ms delay.

### GUI Architecture

```
LockService.exe (non-service mode)
└── Win32 Window
    └── WebView2 (Edge)
        └── React + shadcn/ui (embedded HTML)
```

The configuration GUI uses WebView2 COM interfaces implemented via custom C vtables — no C++ or WebView2 SDK headers required. Communication between JS and C uses JSON messages over `postMessage()` / `ExecuteScript()`. The window auto-sizes to fit content.

## Event Logging

LockService logs to the Windows Event Viewer under the `LockService` source in the Application log. Events include:

- Helper process attach/detach per session
- Win+L detection (with username)
- HTTP API requests
- Errors (socket failures, process creation failures, etc.)

View recent events:
```
wevtutil qe Application /q:"*[System[Provider[@Name='LockService']]]" /c:10 /f:text
```

## Security Notes

- The service runs as LOCAL SYSTEM (required for session enumeration and user token access).
- The HTTP server binds to `0.0.0.0` by default (all interfaces). To restrict to localhost only, set `BindIP` to `127.0.0.1`.
- The HTTP API has no authentication — use firewall rules to restrict access if exposed on a network.
- WebView2 user data is stored in `%TEMP%\LockService.WebView2` (not alongside the executable).

## Building from Source

Requires:
- `x86_64-w64-mingw32-gcc` (MinGW-w64 cross compiler)
- `x86_64-w64-mingw32-windres` (resource compiler)
- Node.js and npm (for building the frontend)

```
make
```

This will:
1. Install frontend dependencies and build the React UI into a single HTML file (`assets/dist/index.html`)
2. Compile Windows resources (manifest, icon, embedded HTML, embedded WebView2Loader.dll)
3. Compile and link the final executable

The compiled binary is placed in `release/LockService.exe`. To rebuild from scratch:

```
make clean && make
```

## License

[MIT](LICENSE)
