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

Double-click `LockService.exe` (as Administrator). A configuration dialog will appear with Install, Uninstall, Start, and Stop buttons. Buttons are grayed out based on the current service state.

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

## HTTP API

With the service running, a single endpoint is available:

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
