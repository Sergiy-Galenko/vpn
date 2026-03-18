# WGDesk / Personal WireGuard VPN Manager

## English

### Overview

This repository currently contains two layers:

1. The current working application in `src/`
   It is a Python app with:
   - a desktop GUI built with `tkinter`
   - a modern console interface
   - WireGuard client generation
   - SQLite-based client storage
   - editable VPN settings via `.env`

2. The new production-oriented architecture in `src/wgdesk/`
   It is the newer modular application that is being built out with:
   - `PySide6`
   - `SQLAlchemy` + `Alembic`
   - local and SSH execution layers
   - agent transport
   - a new desktop shell

If you need the app that is usable right now, start with `python3 -m src.main`.

---

### What this VPN service does

This project manages a personal WireGuard VPN service for secure private access to your own server or home network.

The current application can:
- install and configure WireGuard on Ubuntu
- generate server and client keys
- create ready-to-use client `.conf` files
- start, stop, and restart the VPN service on Linux
- store clients in SQLite
- edit VPN settings through GUI or CLI
- detect the host operating system and disable unsupported local actions

---

### How WireGuard works in this project

1. The server has a WireGuard interface such as `wg0`.
2. The server receives an address such as `10.8.0.1/24`.
3. Each client gets its own key pair and VPN address such as `10.8.0.2/32`.
4. The server configuration is rebuilt to include each client as a `[Peer]`.
5. When the VPN starts, `wg-quick@<interface>` brings the interface up.
6. NAT and IP forwarding are used so VPN traffic can reach the public network.

Generated files:
- `configs/server/wg0.conf`: generated local server configuration
- `configs/clients/<client>.conf`: client configuration
- `configs/keys/server_private.key`: server private key
- `configs/keys/server_public.key`: server public key
- `configs/keys/clients/<client>.key`: client private key
- `data/vpn.sqlite3`: SQLite database
- `data/vpn_manager.log`: application log

Main editable VPN settings:
- `WG_ENDPOINT`
- `WG_INTERFACE_NAME`
- `WG_SERVER_ADDRESS`
- `WG_SERVER_PORT`
- `WG_PUBLIC_INTERFACE`
- `WG_DNS`
- `WG_CLIENT_ALLOWED_IPS`
- `WG_CONNECTED_WINDOW_SECONDS`

You can change them:
- manually in `.env`
- in the GUI `Settings` tab
- with the CLI `configure-vpn` command

---

### Operating system support

#### Ubuntu / Linux

Full local mode is supported:
- install WireGuard
- generate keys
- create client configs
- start / stop / restart VPN
- inspect connected peers
- edit VPN settings
- run GUI or console mode

This is the target host for real WireGuard service control.

#### macOS

macOS is supported as a desktop control client:
- run the GUI
- run the console mode
- inspect system information
- edit VPN settings
- create client configs
- inspect SQLite data and logs

Local Linux-only actions are intentionally blocked:
- `install-vpn`
- `start-vpn`
- `stop-vpn`
- `restart-vpn`
- local connected peer runtime lookup

The application now detects the host OS and shows a clear platform-specific message instead of a generic runtime failure.

#### Windows

Windows support is similar to macOS:
- GUI and console can run
- settings can be edited
- configs and stored data can be viewed

Local Ubuntu-specific service control is not supported on Windows.

---

### Installation

#### Option 1: current application in `src/`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Option 2: new `wgdesk` package

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

---

### How to run the current application

Automatic launch mode selection:

```bash
python3 -m src.main
```

If the session is interactive, the launcher offers:
- `1. Graphical interface`
- `2. Console interface`

Explicit GUI:

```bash
python3 -m src.main gui
```

or

```bash
python3 -m src.main app
```

Explicit console:

```bash
python3 -m src.main console
```

or

```bash
python3 -m src.main menu
```

---

### Main CLI commands

Show detected host platform:

```bash
python3 -m src.main system-info
```

Show current VPN settings:

```bash
python3 -m src.main show-config
```

Update VPN settings:

```bash
python3 -m src.main configure-vpn \
  --endpoint vpn.example.com \
  --interface wg1 \
  --server-address 10.20.30.1/24 \
  --port 51830 \
  --public-interface eth0 \
  --dns "1.1.1.1,8.8.8.8" \
  --allowed-ips "0.0.0.0/0, ::/0" \
  --connected-window 300
```

Add a client:

```bash
python3 -m src.main add-client --name phone
```

Remove a client:

```bash
python3 -m src.main remove-client --name phone
```

List clients:

```bash
python3 -m src.main list-clients
```

Show connected peers:

```bash
python3 -m src.main show-connected
```

On macOS and Windows, the app explains that peer runtime lookup is available only on the Linux host where WireGuard is running.

---

### Running WireGuard locally on Ubuntu

These commands must be executed on the Ubuntu server that actually runs WireGuard.

Install WireGuard:

```bash
sudo python3 -m src.main install-vpn
```

Start VPN:

```bash
sudo python3 -m src.main start-vpn
```

Stop VPN:

```bash
sudo python3 -m src.main stop-vpn
```

Restart VPN:

```bash
sudo python3 -m src.main restart-vpn
```

Why `sudo` is required:
- the app writes into `/etc/wireguard`
- the app uses `systemctl`
- the app changes sysctl settings
- the app manages the local WireGuard service

---

### Detailed startup instructions by operating system

#### macOS

1. Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create the environment file:

```bash
cp .env.example .env
```

4. Start the app:

```bash
python3 -m src.main
```

Typical macOS usage:
- edit VPN settings
- create client configs
- review stored data and logs
- use GUI or console mode as a desktop control client

What not to expect on macOS:
- local `systemctl`
- local `wg-quick@wg0`
- local Ubuntu service management

#### Ubuntu / Debian / Linux

1. Install Python and venv:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv
```

2. Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Create `.env`:

```bash
cp .env.example .env
```

5. Edit the endpoint and network settings, for example:

```dotenv
WG_ENDPOINT=vpn.example.com
WG_INTERFACE_NAME=wg0
WG_SERVER_ADDRESS=10.8.0.1/24
WG_SERVER_PORT=51820
WG_PUBLIC_INTERFACE=eth0
WG_DNS=1.1.1.1,8.8.8.8
WG_CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0
WG_CONNECTED_WINDOW_SECONDS=180
```

6. Install and prepare WireGuard:

```bash
sudo python3 -m src.main install-vpn
```

7. Add clients:

```bash
python3 -m src.main add-client --name laptop
python3 -m src.main add-client --name phone
```

8. Start the service:

```bash
sudo python3 -m src.main start-vpn
```

9. Inspect status:

```bash
python3 -m src.main list-clients
python3 -m src.main show-connected
```

#### Windows

1. Create a virtual environment:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Start the app:

```powershell
py -3 -m src.main
```

Typical Windows usage:
- GUI / console mode
- editing `.env`
- generating client configs
- viewing stored data

Windows is not a local target for `systemctl` or `/etc/wireguard`.

---

### GUI mode

The current GUI includes:
- dashboard
- clients view
- connected peers view
- files and logs view
- settings tab

Important behavior:
- Linux-only controls are disabled automatically on macOS and Windows
- the `Settings` tab lets you change VPN parameters without editing `.env` manually

---

### Console mode

`console` and `menu` now open a modern terminal UI with:
- dashboard
- system info
- show VPN settings
- edit VPN settings
- add / remove client
- list clients
- show connected peers
- install / start / stop / restart VPN
- open GUI from console

---

### New `wgdesk` architecture

The `src/wgdesk/` tree contains the newer production-oriented architecture:
- `PySide6`
- `SQLAlchemy`
- `Alembic`
- SSH executor
- agent transport
- new GUI shell

Run it with:

```bash
pip install -e .[dev]
python -m wgdesk.app
```

This path is still under active development, but the codebase is already structured for:
- local Ubuntu mode
- remote Ubuntu management over SSH
- audit logging
- QR export
- modular services and repositories

---

### Logs and diagnostics

Application log:

```text
data/vpn_manager.log
```

Common reasons for problems:

1. Running `start-vpn` on macOS or Windows
   Local service control is supported only on the Ubuntu/Linux host running WireGuard.

2. Missing `wg`
   WireGuard tools must exist on the Linux host.

3. Missing `sudo`
   Install / start / stop / restart operations need elevated privileges on Ubuntu.

4. Invalid `WG_ENDPOINT`
   Client configs may still be generated, but connections will not work correctly.

---

### Useful commands

```bash
python3 -m src.main system-info
python3 -m src.main show-config
python3 -m src.main console
python3 -m src.main gui
python3 -m src.main add-client --name phone
python3 -m src.main list-clients
sudo python3 -m src.main install-vpn
sudo python3 -m src.main start-vpn
```

---

## Українська

### Огляд

Цей репозиторій зараз містить два шари:

1. Поточний робочий застосунок у `src/`
   Це Python-додаток з:
   - графічним інтерфейсом на `tkinter`
   - сучасним консольним інтерфейсом
   - генерацією клієнтів WireGuard
   - збереженням клієнтів у SQLite
   - редагуванням VPN-параметрів через `.env`

2. Нова production-oriented архітектура у `src/wgdesk/`
   Це новий модульний застосунок, який зараз активно добудовується, з:
   - `PySide6`
   - `SQLAlchemy` + `Alembic`
   - локальним та SSH execution layer
   - agent transport
   - новою desktop-оболонкою

Якщо потрібен застосунок, який уже можна використовувати зараз, запускай `python3 -m src.main`.

---

### Що робить цей VPN сервіс

Проєкт керує персональним WireGuard VPN для безпечного приватного доступу до власного сервера або домашньої мережі.

Поточний застосунок уміє:
- встановлювати та конфігурувати WireGuard на Ubuntu
- генерувати серверні та клієнтські ключі
- створювати готові клієнтські `.conf`
- запускати, зупиняти і перезапускати VPN сервіс на Linux
- зберігати клієнтів у SQLite
- редагувати VPN-параметри через GUI або CLI
- визначати ОС хоста і відключати непідтримувані локальні дії

---

### Як WireGuard працює в цьому проєкті

1. Сервер має WireGuard-інтерфейс, наприклад `wg0`.
2. Сервер отримує адресу, наприклад `10.8.0.1/24`.
3. Кожен клієнт отримує власну пару ключів і VPN-адресу, наприклад `10.8.0.2/32`.
4. Серверний конфіг перебудовується так, щоб додати кожного клієнта як `[Peer]`.
5. Коли VPN запускається, `wg-quick@<interface>` піднімає інтерфейс.
6. NAT та IP forwarding дають змогу VPN-трафіку виходити в публічну мережу.

Файли, які створюються:
- `configs/server/wg0.conf` — локально згенерований серверний конфіг
- `configs/clients/<client>.conf` — клієнтський конфіг
- `configs/keys/server_private.key` — приватний ключ сервера
- `configs/keys/server_public.key` — публічний ключ сервера
- `configs/keys/clients/<client>.key` — приватний ключ клієнта
- `data/vpn.sqlite3` — SQLite база
- `data/vpn_manager.log` — лог застосунку

Основні VPN-параметри:
- `WG_ENDPOINT`
- `WG_INTERFACE_NAME`
- `WG_SERVER_ADDRESS`
- `WG_SERVER_PORT`
- `WG_PUBLIC_INTERFACE`
- `WG_DNS`
- `WG_CLIENT_ALLOWED_IPS`
- `WG_CONNECTED_WINDOW_SECONDS`

Їх можна змінювати:
- вручну в `.env`
- у вкладці `Settings` в GUI
- через CLI-команду `configure-vpn`

---

### Підтримка операційних систем

#### Ubuntu / Linux

Підтримується повний локальний сценарій:
- install WireGuard
- generate keys
- create client configs
- start / stop / restart VPN
- show connected peers
- edit VPN settings
- GUI або console mode

Саме це є цільовим хостом для реального керування WireGuard service.

#### macOS

macOS підтримується як desktop control client:
- запуск GUI
- запуск console mode
- перегляд системної інформації
- редагування VPN-параметрів
- створення клієнтських конфігів
- перегляд SQLite та логів

Локальні Linux-only дії навмисно заблоковані:
- `install-vpn`
- `start-vpn`
- `stop-vpn`
- `restart-vpn`
- локальний runtime lookup підключених peers

Застосунок уже визначає ОС хоста і показує зрозуміле повідомлення замість абстрактної помилки.

#### Windows

Підтримка Windows подібна до macOS:
- GUI та console запускаються
- параметри можна редагувати
- конфіги і збережені дані можна переглядати

Локальне Ubuntu-specific керування сервісом на Windows не підтримується.

---

### Встановлення

#### Варіант 1: поточний застосунок у `src/`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Варіант 2: новий пакет `wgdesk`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

---

### Як запускати поточний застосунок

Автовибір режиму:

```bash
python3 -m src.main
```

Якщо сесія інтерактивна, launcher запропонує:
- `1. Graphical interface`
- `2. Console interface`

Явно GUI:

```bash
python3 -m src.main gui
```

або

```bash
python3 -m src.main app
```

Явно console:

```bash
python3 -m src.main console
```

або

```bash
python3 -m src.main menu
```

---

### Основні CLI-команди

Показати визначену платформу:

```bash
python3 -m src.main system-info
```

Показати поточні VPN-параметри:

```bash
python3 -m src.main show-config
```

Оновити VPN-параметри:

```bash
python3 -m src.main configure-vpn \
  --endpoint vpn.example.com \
  --interface wg1 \
  --server-address 10.20.30.1/24 \
  --port 51830 \
  --public-interface eth0 \
  --dns "1.1.1.1,8.8.8.8" \
  --allowed-ips "0.0.0.0/0, ::/0" \
  --connected-window 300
```

Додати клієнта:

```bash
python3 -m src.main add-client --name phone
```

Видалити клієнта:

```bash
python3 -m src.main remove-client --name phone
```

Показати клієнтів:

```bash
python3 -m src.main list-clients
```

Показати підключених peers:

```bash
python3 -m src.main show-connected
```

На macOS і Windows застосунок пояснить, що runtime lookup доступний лише на Linux-хості, де реально працює WireGuard.

---

### Локальне керування WireGuard на Ubuntu

Нижче команди, які потрібно запускати саме на Ubuntu-сервері, де встановлений WireGuard.

Встановити WireGuard:

```bash
sudo python3 -m src.main install-vpn
```

Запустити VPN:

```bash
sudo python3 -m src.main start-vpn
```

Зупинити VPN:

```bash
sudo python3 -m src.main stop-vpn
```

Перезапустити VPN:

```bash
sudo python3 -m src.main restart-vpn
```

Чому потрібен `sudo`:
- застосунок пише в `/etc/wireguard`
- застосунок викликає `systemctl`
- застосунок змінює sysctl
- застосунок керує локальним WireGuard service

---

### Детальний запуск на різних ОС

#### macOS

1. Створи virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Встанови залежності:

```bash
pip install -r requirements.txt
```

3. Створи `.env`:

```bash
cp .env.example .env
```

4. Запусти застосунок:

```bash
python3 -m src.main
```

Типове використання на macOS:
- редагування VPN-параметрів
- створення клієнтських конфігів
- перегляд збережених даних і логів
- запуск GUI або console mode як desktop control client

Чого не слід очікувати на macOS:
- локального `systemctl`
- локального `wg-quick@wg0`
- локального Ubuntu service management

#### Ubuntu / Debian / Linux

1. Встанови Python і venv:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv
```

2. Створи virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Встанови Python-залежності:

```bash
pip install -r requirements.txt
```

4. Створи `.env`:

```bash
cp .env.example .env
```

5. Відредагуй endpoint і мережеві параметри, наприклад:

```dotenv
WG_ENDPOINT=vpn.example.com
WG_INTERFACE_NAME=wg0
WG_SERVER_ADDRESS=10.8.0.1/24
WG_SERVER_PORT=51820
WG_PUBLIC_INTERFACE=eth0
WG_DNS=1.1.1.1,8.8.8.8
WG_CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0
WG_CONNECTED_WINDOW_SECONDS=180
```

6. Встанови та підготуй WireGuard:

```bash
sudo python3 -m src.main install-vpn
```

7. Додай клієнтів:

```bash
python3 -m src.main add-client --name laptop
python3 -m src.main add-client --name phone
```

8. Запусти сервіс:

```bash
sudo python3 -m src.main start-vpn
```

9. Перевір стан:

```bash
python3 -m src.main list-clients
python3 -m src.main show-connected
```

#### Windows

1. Створи virtual environment:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Встанови залежності:

```powershell
pip install -r requirements.txt
```

3. Запусти застосунок:

```powershell
py -3 -m src.main
```

Типове використання на Windows:
- GUI / console mode
- редагування `.env`
- генерація клієнтських конфігів
- перегляд збережених даних

Windows не є локальним target для `systemctl` або `/etc/wireguard`.

---

### GUI режим

Поточний GUI містить:
- dashboard
- clients view
- connected peers view
- files and logs view
- settings tab

Важлива поведінка:
- Linux-only елементи керування автоматично відключаються на macOS і Windows
- вкладка `Settings` дозволяє змінювати VPN-параметри без ручного редагування `.env`

---

### Console режим

`console` і `menu` тепер відкривають сучасний terminal UI з:
- dashboard
- system info
- show VPN settings
- edit VPN settings
- add / remove client
- list clients
- show connected peers
- install / start / stop / restart VPN
- open GUI from console

---

### Нова архітектура `wgdesk`

Дерево `src/wgdesk/` містить нову production-oriented архітектуру:
- `PySide6`
- `SQLAlchemy`
- `Alembic`
- SSH executor
- agent transport
- new GUI shell

Запуск:

```bash
pip install -e .[dev]
python -m wgdesk.app
```

Цей шлях ще активно добудовується, але кодова база вже підготовлена для:
- local Ubuntu mode
- remote Ubuntu management over SSH
- audit logging
- QR export
- modular services and repositories

---

### Логи і діагностика

Лог застосунку:

```text
data/vpn_manager.log
```

Типові причини проблем:

1. Запуск `start-vpn` на macOS або Windows
   Локальне керування сервісом підтримується лише на Ubuntu/Linux-хості, де реально працює WireGuard.

2. Відсутній `wg`
   На Linux-хості мають бути встановлені WireGuard tools.

3. Не використано `sudo`
   Для install / start / stop / restart на Ubuntu потрібні підвищені права.

4. Невірний `WG_ENDPOINT`
   Клієнтські конфіги можуть згенеруватися, але підключення не працюватиме коректно.

---

### Корисні команди

```bash
python3 -m src.main system-info
python3 -m src.main show-config
python3 -m src.main console
python3 -m src.main gui
python3 -m src.main add-client --name phone
python3 -m src.main list-clients
sudo python3 -m src.main install-vpn
sudo python3 -m src.main start-vpn
```
