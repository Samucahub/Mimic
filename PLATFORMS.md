# MIMIC Honeypot - Platform Compatibility

## Supported Platforms

### ✅ Windows
- **Tested on:** Windows 10, Windows 11
- **Python:** 3.11+
- **Installation:** `pip install -r requirements.txt`
- **Run:** `python configurator.py`
- **Kill:** `.\kill_honeypot.ps1`

### ✅ Linux
- **Tested on:** Ubuntu 20.04+, Debian 11+
- **Python:** 3.11+
- **Installation:** `pip3 install -r requirements.txt`
- **Run:** `python3 configurator.py` or `sudo python3 configurator.py` (for privileged ports)
- **Kill:** `./kill_honeypot.sh`
- **Startup script:** `./start_mimic.sh`

### ⚠️ macOS
- **Status:** Should work (not extensively tested)
- **Python:** 3.11+
- **Notes:** Same as Linux instructions

## Port Privileges

### Privileged Ports (<1024)
These ports require administrator/root privileges:

| Port | Service | Windows | Linux |
|------|---------|---------|-------|
| 21   | FTP     | ✅ Works | ⚠️ Needs sudo |
| 22   | SSH     | ✅ Works | ⚠️ Needs sudo |
| 23   | Telnet  | ✅ Works | ⚠️ Needs sudo |
| 80   | HTTP    | ✅ Works | ⚠️ Needs sudo |

### Non-Privileged Ports (≥1024)
These ports work without special privileges:

| Port | Service | Windows | Linux |
|------|---------|---------|-------|
| 3306 | MySQL   | ✅ Works | ✅ Works |
| 3389 | RDP     | ✅ Works | ✅ Works |

## Running with Elevated Privileges

### Windows
Run PowerShell as Administrator:
```powershell
# Right-click PowerShell → Run as Administrator
python configurator.py
```

### Linux
Use sudo:
```bash
sudo python3 configurator.py
```

Or set capabilities (recommended for production):
```bash
# Allow Python to bind to privileged ports
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3.11
python3 configurator.py
```

## Known Platform Differences

### Process Management
- **Windows:** Uses `taskkill` command
- **Linux:** Uses `pkill` and `kill` commands

### Port Detection
- **Windows:** Uses `netstat -ano`
- **Linux:** Uses `lsof -ti:PORT`

### GUI (pygame)
- **Windows:** Works out of the box
- **Linux:** May require additional packages:
  ```bash
  sudo apt-get install python3-pygame
  # or for full SDL support
  sudo apt-get install libsdl2-dev libsdl2-image-dev libsdl2-mixer-dev libsdl2-ttf-dev
  ```

## Troubleshooting

### Linux: "pygame not found"
```bash
sudo apt-get update
sudo apt-get install python3-pygame
# or
pip3 install pygame
```

### Linux: "Permission denied" on ports 22, 21, 80, 23
```bash
# Run with sudo
sudo python3 configurator.py

# Or use setcap (permanent solution)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

### Windows: "Port already in use"
```powershell
# Check what's using the port
netstat -ano | findstr ":22"

# Kill the process
taskkill /F /PID <PID>

# Or use the kill script
.\kill_honeypot.ps1
```

### Linux: "Port already in use"
```bash
# Check what's using the port
lsof -i :22

# Kill the process
kill -9 <PID>

# Or use the kill script
./kill_honeypot.sh
```

## Cross-Platform Features

### ✅ Fully Compatible
- SSH honeypot
- Configuration system (YAML)
- Logging (JSON)
- Visual configurator (pygame)
- Multi-OS simulation (Ubuntu, Debian, CentOS, Windows, Kali)

### 🚧 Platform-Specific
- Process termination commands
- Port detection utilities
- Privilege escalation requirements

## Development Notes

The codebase automatically detects the platform using:
```python
import platform
if platform.system() == 'Windows':
    # Windows-specific code
else:
    # Linux/Unix-specific code
```

This ensures the honeypot works seamlessly on both Windows and Linux without manual configuration.
