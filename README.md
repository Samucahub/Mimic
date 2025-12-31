
<p align="center">
  <img src="/assets/mimic_banner.png" alt="banner"/>
</p>
<h1 align="center">
 (BETA)
</h1>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

**On stage, everyone thinks they're the star. But the only thing they are, is the show.**

*Every door is a mask. The audience is watching.*

</div>
---

## Features

### Service Emulation
- **SSH** - Full interactive shell with realistic filesystem
- **FTP** - File transfer protocol emulation
- **HTTP** - Web server honeypot
- **Telnet** - Legacy protocol support
- **MySQL** - Database service emulation
- **RDP** - Remote Desktop Protocol (planned)

### Security Features
- **Credential Harvesting** - Capture usernames and passwords
- **Session Logging** - JSON-formatted logs for analysis
- **Human Behavior Simulation** - Realistic response delays
- **Customizable Authentication** - Accept any credentials or enforce specific ones
- **Port Flexibility** - Configure any port for any service

### Advanced Capabilities
- **Multi-OS Simulation** - Convincing banners for different operating systems
- **Interactive Shell** - Command execution and file exploration
- **Filesystem Virtualization** - Realistic directory structures
- **Command Logging** - Track every attacker action
- **IP Tracking** - Monitor connection sources

---

## Quick Start

### Prerequisites

**Windows:**
```bash
# Python 3.11 or higher
python --version

# Install dependencies
pip install -r requirements.txt
```

**Linux/Ubuntu:**
```bash
# Python 3.11 or higher
python3 --version


# Or manual installation
sudo apt-get update
sudo apt-get install python3 python3-pip python3-pygame
sudo pip3 install pyyaml asyncssh pygame

# For ports below 1024, you'll need root privileges
sudo python3 mimic.py
```

### Installation

**Windows:**
```bash
Download of the last Mimic release

OR

# Clone the repository
git clone https://github.com/Samucahub/mimic.git

After:
cd mimic

# Install dependencies
pip install -r requirements.txt
```

**Ubuntu/Linux:**
```bash
Download of the last Mimic release

OR

# Clone the repository
git clone https://github.com/Samucahub/mimic.git

After:
cd mimic

sudo pip3 install -r requirements.txt
```

### Running MIMIC

#### Option 1: Visual Configurator (Recommended)

**Windows:**
```bash
python mimic.py
```

**Linux:**
```bash
# Normal ports (>1024)
python3 mimic.py

# For privileged ports (21, 22, 23, 80)
sudo python3 mimic.py

# Or use the startup script
chmod +x start_mimic.sh
./start_mimic.sh
```

1. Configure identity (username, password, hostname)
2. Select OS template (Ubuntu, Debian, CentOS, Windows, Kali)
3. Enable desired services (SSH, FTP, HTTP, etc.)
4. Set honeypot mode (accept any credentials or enforce specific ones)
5. Click **"Let the show begin!"**
6. Monitor live activity
7. Click **"Close the curtains"** to stop

#### Option 2: Direct Execution

```bash
# Edit config/honeypot.yaml first
python main.py
```

---

## Configuration

### Example Configuration

```yaml
system:
  username: admin
  password: admin123
  hostname: web-server
  os_template: Ubuntu

options:
  any_auth: false
  enable_logging: true
  human_patterns: false
  log_retention_days: 7
security:
  enabled: true
  ip_blocking:
    auto_block_failed_logins: 10
  rate_limits:
    block_duration_minutes: 60
    max_connections_per_minute: 60
    max_failed_logins: 10
    window_seconds: 60

services:
  '21':
    allow_download: false
    allow_upload: false
    anonymous_login: true
    banner: 220 ProFTPD 1.3.5 Server (Debian)
    enabled: true
    max_file_size: 104857600  #100 MB
    type: ftp
  '22':
    banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
    enabled: true
    type: ssh
  '23':
    enabled: true
    type: telnet
```

### OS Templates(Future)

| Template | Description | Banner |
|----------|-------------|--------|
| **Ubuntu** | Ubuntu 18.04.6 LTS | GNU/Linux 4.15.0-20-generic x86_64 |
| **Debian** | Debian 11 (bullseye) | Debian GNU/Linux 11 |
| **CentOS** | CentOS 7.9.2009 | CentOS Linux release 7.9.2009 (Core) |
| **Windows** | Windows Server 2019 | Microsoft Windows Server 2019 Standard |
| **Kali** | Kali Linux Rolling | Kali GNU/Linux Rolling |

---

## Usage Examples

### Honeypot Mode (Accept Any Credentials)

```yaml
options:
  any_auth: true
```

Attackers can login with **any** username/password combination. Perfect for capturing credential attempts.

### Authenticated Mode (Specific Credentials Only)

```yaml
options:
  any_auth: false
system:
  username: admin
  password: secret123
```

Only accepts the configured username and password. Rejects all others.

### Testing the Honeypot

```bash
# SSH Connection
ssh admin@192.168.1.100 -p 22

# FTP Connection
ftp 192.168.1.100 or Filezila

# Scan with Nmap
nmap -sV 192.168.1.100
```

---

## Monitoring & Logs

### Log Files

```
logs/
├── ssh_honeypot.jsonl      # SSH session logs
├── ftp_honeypot.jsonl      # FTP connection logs
├── http_honeypot.jsonl     # HTTP request logs
└── honeypot_output.log     # Main system log
```

### FTP Storage

All files sent via FTP end up in this folder storage.

```
ftp_storage/
└── home      # Users in system
    ├── Public
    |   ├── Desktop
    |   ├── Documents
    |   └── ...
    └── User
        ├── Desktop
        ├── Documents
        |   └── notes.txt
        ├── ...
        └── welcome.txt
```

### Log Format (JSON Lines)

```json
{
  "timestamp": "2025-12-24T17:30:45.123456",
  "event": "login_attempt",
  "service": "ssh",
  "port": 22,
  "client_ip": "192.168.1.50",
  "username": "admin",
  "password": "password123",
  "success": true,
  "valid_credentials": false,
  "any_auth_mode": true
}
```

---

## Development

### Project Structure

```
mimic/
├── main.py                 # Entry point
├── mimic.py                # Visual GUI
├── config/
│   ├── honeypot.yaml      # Main configuration
│   └── templates/         # OS templates
├── core/
│   ├── controller.py      # Service orchestration
│   ├── port_manager.py    # Port validation
│   ├── security_layer.py  # Security checks
│   └── service_emulator/
│       ├── ssh_emulator.py
│       ├── ftp_emulator.py
│       ├── http_emulator.py
│       └── ...
├── log_system/
│   └── session_logger.py  # Logging framework
└── logs/                  # Generated logs
```

### Adding New Services

1. Create emulator in `core/service_emulator/`
2. Inherit from `BaseService`
3. Implement `handle_connection()`
4. Register in `controller.py`

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Security

Found a security vulnerability? Please see [SECURITY.md](SECURITY.md) for reporting guidelines.

---

## :coffee: Buy Me a Coffee

<a href="https://www.buymeacoffee.com/samunana" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

## Follow Me

<p>
  <a href="https://x.com/CyberSamu_">
        <img src="https://img.shields.io/badge/X-000000?style=for-the-badge&logo=twitter&logoColor=white"/>
  </a>
  <a href="https://www.linkedin.com/in/samuel-rocha-3a630731a/">
        <img src="https://img.shields.io/static/v1?message=LinkedIn&logo=linkedin&label=&color=0077B5&logoColor=white&labelColor=&style=for-the-badge" height="35" alt="linkedin logo"  />
  </a>
</p>

## Acknowledgments

- **asyncssh** - Robust SSH protocol implementation
- **Pygame** - Visual interface framework
- Inspired by classic honeypot projects like Cowrie and Kippo
- Theatrical aesthetic inspired by mime performance art

---

## Contact

**Author:** The Architect  
**GitHub:** [@Samucahub](https://github.com/Samucahub)  
**Project:** [MIMIC Honeypot](https://github.com/Samucahub/mimic)

---

<div align="center">

**🎭 The stage is set. The audience watches. 🎭**

*Let the show begin!*

</div>



















