# LockService

A lightweight Windows service that locks workstations and turns off monitors, controllable via HTTP API and Win+L hotkey interception.

## What It Does

LockService runs as a Windows service and provides two ways to lock the screen and power off monitors:

- **HTTP API** — Send a GET request to `http://localhost:8888/lock` to lock all active sessions and turn off monitors. Useful for automation, scripts, or triggering a lock from another machine on the network.
- **Win+L Interception** — The service attaches a keyboard hook helper into each active user session. When Win+L is pressed, it locks the workstation and immediately turns off monitors (the default Windows behavior only locks without powering off displays).

The service automatically tracks user sessions — attaching helpers when users log in and cleaning them up when sessions end.

## Installation

### Requirements

- Windows 10/11 (x86_64)
- Administrator privileges

### Using the GUI

Double-click `LockService.exe` (as Administrator). A configuration dialog will appear with:

- **Bind IP / Bind Port** fields to configure what address and port the HTTP server listens on (defaults: `0.0.0.0` / `8888`). Changes are saved to the registry and take effect on the next service start. If the service is already running, saving will automatically restart it.
- **Install**, **Uninstall**, **Restart**, **Start**, and **Stop** buttons (grayed out based on current service state).
- Colored status indicator — green when running, red when stopped.

If launched without admin privileges, a warning dialog will prompt you to re-run as Administrator.

### Using the Command Line

```
LockService.exe install
LockService.exe uninstall
```

Once installed, the service starts automatically on boot. You can also manage it through `services.msc` or `sc`:

```
sc start LockService
sc stop LockService
```

## Configuration

Settings are stored in the registry at `HKLM\SOFTWARE\JPIT\LockService`:

| Value      | Type      | Default   | Description                        |
|------------|-----------|-----------|------------------------------------|
| `BindIP`   | REG_SZ    | `0.0.0.0` | IP address the HTTP server binds to |
| `BindPort` | REG_DWORD | `8888`    | Port the HTTP server listens on     |

These can be edited through the GUI dialog or directly in the registry for headless/scripted setups.

## HTTP API

With the service running, a single endpoint is available (port is configurable, default `8888`):

```
GET http://localhost:8888/lock
```

Response:
```json
{"status":"ok","message":"Sessions locked"}
```

This locks all active user sessions and turns off monitors.

## Building from Source

Requires `x86_64-w64-mingw32-gcc` (MinGW-w64 cross compiler):

```
make
```

The compiled binary is placed in `release/LockService.exe`.

## License

MIT
