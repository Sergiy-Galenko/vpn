# Personal WireGuard VPN Manager

This project is a small Python 3.11+ application for managing a personal WireGuard VPN service on Ubuntu.

It can:

- install WireGuard with `apt-get`
- generate server and client keys
- create server and client `.conf` files
- enable IP forwarding
- start, stop, and restart the VPN service
- list saved clients
- show recently connected clients
- store client data in SQLite
- run from Python code or terminal commands

## Project structure

```text
.
├── configs/
│   ├── clients/
│   ├── keys/
│   └── server/
├── data/
├── tests/
│   └── test_wireguard_manager.py
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── main.py
│   ├── models.py
│   ├── storage.py
│   ├── utils.py
│   └── wireguard_manager.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

- Ubuntu server for real WireGuard install and service control
- Python 3.11+
- Root privileges for install, IP forwarding, and `systemctl` actions

## Setup

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create your environment file:

   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and set `WG_ENDPOINT` to your Ubuntu server public IP or DNS name.

## Run the CLI menu

Use the interactive menu:

```bash
python3 -m src.main
```

Use root for install and service management:

```bash
sudo python3 -m src.main
```

## Terminal commands

Install and configure WireGuard:

```bash
sudo python3 -m src.main install-vpn
```

Add a client:

```bash
sudo python3 -m src.main add-client --name phone
```

Remove a client:

```bash
sudo python3 -m src.main remove-client --name phone
```

List all stored clients:

```bash
python3 -m src.main list-clients
```

Show recently connected clients:

```bash
python3 -m src.main show-connected
```

Start the VPN:

```bash
sudo python3 -m src.main start-vpn
```

Stop the VPN:

```bash
sudo python3 -m src.main stop-vpn
```

Restart the VPN:

```bash
sudo python3 -m src.main restart-vpn
```

## What gets generated

- SQLite database: `data/vpn.sqlite3`
- Log file: `data/vpn_manager.log`
- Local server config: `configs/server/wg0.conf`
- Client config files: `configs/clients/<client-name>.conf`
- Server keys: `configs/keys/server_private.key` and `configs/keys/server_public.key`
- Client private keys: `configs/keys/clients/<client-name>.key`

During root operations on Ubuntu, the generated server config is also copied to `/etc/wireguard/wg0.conf` by default.

SQLite stores client metadata only. Client private keys are kept in `configs/keys/clients/` with `0600` file permissions instead of being stored in the database.

## How connected clients are detected

WireGuard does not provide a strict online/offline state. This project treats a client as connected when its latest handshake is newer than `WG_CONNECTED_WINDOW_SECONDS`.

## Use from Python code

```python
from src.config import load_config
from src.storage import ClientStorage
from src.wireguard_manager import WireGuardManager

config = load_config()
storage = ClientStorage(config.database_path, config.client_private_keys_dir)
manager = WireGuardManager(config, storage)

manager.create_server_config()
client = manager.add_client("laptop")
print(client.config_path)
```

## Notes

- Run install and service actions on Ubuntu, not macOS or Windows.
- `add-client` requires the `wg` command to exist because key generation uses WireGuard tools.
- Client config files contain private keys, so keep them secure.

## Run tests

```bash
python3 -m unittest discover -s tests
```
