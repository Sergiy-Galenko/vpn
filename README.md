# WGDesk

`WGDesk` is a PySide6 desktop application for managing a WireGuard server in:

- local Ubuntu mode
- remote Ubuntu mode over SSH from macOS

The application uses:

- PySide6 for GUI
- SQLAlchemy + Alembic for persistence
- a structured Python server agent for local and remote execution
- SQLite for local state
- secret storage abstraction
- QR export for client configs

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
alembic upgrade head
python -m wgdesk.app
```

## Current slices implemented

- create and persist local/SSH server profiles
- connect to local or remote agent
- fetch server status
- append audit log entries
- create, disable and enable clients
- immediate QR generation after client creation

## Build

```bash
pyinstaller packaging/wgdesk.spec --noconfirm
```

