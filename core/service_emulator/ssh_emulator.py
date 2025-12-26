import asyncio
import asyncssh
import json
import random
from datetime import datetime
from pathlib import Path

class SSHService:
    
    def __init__(self, port: int, config: dict, security_layer=None):
        self.port = port
        self.config = config
        self.security = security_layer
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3')
        
        self.any_auth = config.get('any_auth', True)
        self.username = config.get('username', 'admin')
        self.enable_scp = config.get('enable_scp', True)
        
        if not self.any_auth:
            self.users = {self.username: config.get('password', 'admin123')}
        else:
            self.users = config.get('users', {
                'admin': 'admin123',
                'root': 'password',
                'user': '123456',
                'test': 'test'
            })
        
        self.is_running = False
        self.server = None
        self.server_task = None
        self.host_key = None
        
        self.hostname = config.get('hostname', self._generate_realistic_hostname())
        
        Path("logs").mkdir(exist_ok=True)
        self.log_file = "logs/ssh_honeypot.jsonl"
    
    def _generate_realistic_hostname(self):
        prefixes = ['ubuntu', 'web', 'db', 'mail', 'app', 'srv', 'prod', 'dev']
        suffixes = ['server', 'srv', 'host', 'node']
        
        if random.random() < 0.5:
            return f"{random.choice(prefixes)}-{random.choice(suffixes)}-{random.randint(1, 99):02d}"
        else:
            return f"{random.choice(prefixes)}-{random.choice(suffixes)}"
    
    def log_event(self, event_type: str, details: dict):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            "service": "ssh",
            "port": self.port,
            **details
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            if event_type == "connection":
                print(f"[SSH] Connection from {details.get('client_ip')}")
            elif event_type == "login_attempt":
                status = "✓" if details.get('success') else "✗"
                print(f"[SSH] {status} Login: {details.get('username')} from {details.get('client_ip')}")
            elif event_type == "command":
                print(f"[SSH] Cmd: {details.get('username')}: {details.get('command')}")
            elif event_type == "scp_upload":
                print(f"[SSH] 📤 SCP Upload: {details.get('filename')} ({details.get('size')} bytes)")
            elif event_type == "scp_download":
                print(f"[SSH] 📥 SCP Download: {details.get('filename')}")
        except:
            pass
    
    async def start(self):
        print(f"[SSH] Starting SSH honeypot on port {self.port}")
        print(f"[SSH] Security enabled: {self.security is not None}")
        print(f"[SSH] SCP enabled: {self.enable_scp}")
        print(f"[SSH] Logs: {self.log_file}")
        
        self.is_running = True
        
        try:
            key_path = Path("logs/ssh_host_key")
            if key_path.exists():
                self.host_key = asyncssh.read_private_key(str(key_path))
            else:
                self.host_key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
                key_path.write_bytes(self.host_key.export_private_key())
                print(f"[SSH] Generated host key")
            
            print(f"[SSH] Creating server on port {self.port}...")
            self.server = await asyncssh.create_server(
                lambda: SSHServer(self),
                '0.0.0.0',
                self.port,
                server_host_keys=[self.host_key],
                server_version=self.banner.replace('SSH-2.0-', ''),
                reuse_address=True,
                login_timeout=60
            )
            
            if self.server:
                sockets = self.server.sockets
                if sockets:
                    print(f"[SSH] Server created successfully")
                    print(f"[SSH] Socket bound to: {sockets[0].getsockname()}")
                    print(f"[SSH] Listening on 0.0.0.0:{self.port}")
                    print(f"[SSH] Test: ssh admin@localhost -p {self.port} (password: admin123)")
                else:
                    print(f"[SSH] ERROR: No sockets bound!")
                    return
                
                await self.server.wait_closed()
            else:
                print(f"[SSH] ERROR: Server is None!")
                
        except asyncssh.Error as e:
            print(f"[SSH] AsyncSSH Error: {e}")
            import traceback
            traceback.print_exc()
        except OSError as e:
            print(f"[SSH] OSError: {e}")
            if e.errno == 10013:
                print(f"[SSH] ⚠ Port {self.port} requires Administrator privileges")
            else:
                print(f"[SSH] Cannot bind: {e}")
            import traceback
            traceback.print_exc()
        except asyncio.CancelledError:
            print(f"[SSH] Service cancelled")
        except Exception as e:
            print(f"[SSH] Unexpected Error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_running = False
            
    async def stop(self):
        print(f"[SSH] Stopping...")
        self.is_running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class SSHServer(asyncssh.SSHServer):
    
    def __init__(self, ssh_service):
        self.ssh_service = ssh_service
        self.connection_closed = False
        
    def connection_made(self, conn):
        self.conn = conn
        client_ip = conn.get_extra_info('peername')[0]
        
        # Verificar se IP está bloqueado
        if self.ssh_service.security and not self.ssh_service.security.is_ip_allowed(client_ip):
            print(f"[SECURITY] Blocked connection from {client_ip}")
            self.ssh_service.log_event("blocked_connection", {
                "client_ip": client_ip,
                "reason": "IP blocked"
            })
            # Fechar a conexão imediatamente sem enviar banner
            self.connection_closed = True
            conn.close()
            return
        
        # Registrar conexão
        if self.ssh_service.security:
            self.ssh_service.security.record_connection(client_ip)
        
        self.ssh_service.log_event("connection", {"client_ip": client_ip})
        
    def begin_auth(self, username):
        # Se a conexão foi fechada, não permitir autenticação
        if hasattr(self, 'connection_closed') and self.connection_closed:
            return False
        return True
        
    def password_auth_supported(self):
        return True
        
    def public_key_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        client_ip = self.conn.get_extra_info('peername')[0]
        
        # Verificar novamente se IP está bloqueado
        if self.ssh_service.security and not self.ssh_service.security.is_ip_allowed(client_ip):
            print(f"[SECURITY] Blocked login attempt from blocked IP: {client_ip}")
            return False
            
        is_valid = username in self.ssh_service.users and self.ssh_service.users[username] == password
        
        accept = True if self.ssh_service.any_auth else is_valid
        
        # Registrar tentativa de login (falha ou sucesso)
        if self.ssh_service.security:
            if not accept or not is_valid:  # Se não aceitar OU credenciais inválidas
                self.ssh_service.security.record_failed_attempt(client_ip)
                print(f"[SECURITY] Failed login attempt from {client_ip}")
                
                # Verificar se deve bloquear
                if not self.ssh_service.security.check_rate_limit(client_ip):
                    print(f"[SECURITY] Blocking IP {client_ip} for too many failed attempts")
                    self.ssh_service.security.temp_block_ip(client_ip)
                    return False
        
        self.ssh_service.log_event("login_attempt", {
            "client_ip": client_ip,
            "username": username,
            "password": password,
            "success": accept,
            "valid_credentials": is_valid,
            "any_auth_mode": self.ssh_service.any_auth
        })
        
        return accept


class SSHServerSession(asyncssh.SSHServerSession):
    
    def __init__(self, ssh_service, username, client_ip, hostname):
        self.ssh_service = ssh_service
        self.username = username
        self.client_ip = client_ip
        self.hostname = hostname
        self.os_template = ssh_service.config.get('os_template', 'Ubuntu')
        self.cwd = f'/home/{username}'
        
        self.filesystem = self._create_filesystem()
        
        self.in_editor = False
        self.editor_file = None
        self.editor_content = []
        self.editor_type = None
        
        self.environment = {
            'USER': username,
            'HOME': f'/home/{username}',
            'SHELL': '/bin/bash',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'PWD': f'/home/{username}',
            'TERM': 'xterm-256color',
            'SSH_CLIENT': f'{client_ip} 12345 22',
            'SSH_CONNECTION': f'{client_ip} 12345 192.168.1.100 22',
            'LANG': 'en_US.UTF-8',
            'LC_ALL': 'en_US.UTF-8'
        }
        
        self.command_history = []
        self.history_index = 0
        
        self.sudo_active = False
        self.sudo_user = None
        
        self.scp_mode = False
        self.scp_filename = None
        self.scp_file_size = 0
        self.scp_received = 0
        
        self.session_start_time = datetime.now()
        self.command_timeout = ssh_service.config.get('command_timeout', 30)
        self.max_session_time = ssh_service.config.get('max_session_time', 3600)
    
    def _create_filesystem(self):
        return {
            '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
            '/home': [self.username, 'ubuntu'],
            f'/home/{self.username}': ['Documents', 'Downloads', 'Pictures', 'Videos', 'Music', 'Desktop', '.bashrc', '.profile', '.ssh', '.bash_history'],
            f'/home/{self.username}/Documents': ['notes.txt', 'report.pdf', 'project'],
            f'/home/{self.username}/Documents/project': ['README.md', 'config.ini', 'setup.sh'],
            f'/home/{self.username}/Downloads': ['setup.sh', 'data.zip', 'installer.deb', 'backup.tar.gz'],
            f'/home/{self.username}/Pictures': ['photo1.jpg', 'photo2.png'],
            f'/home/{self.username}/Videos': ['video.mp4'],
            f'/home/{self.username}/Music': ['song.mp3'],
            f'/home/{self.username}/Desktop': ['work', 'personal'],
            f'/home/{self.username}/Desktop/work': ['project.doc'],
            f'/home/{self.username}/Desktop/personal': ['todo.txt'],
            f'/home/{self.username}/.ssh': ['authorized_keys', 'known_hosts', 'id_rsa', 'id_rsa.pub'],
            '/etc': ['passwd', 'shadow', 'hosts', 'hostname', 'network', 'ssh', 'cron.d', 'nginx', 'apache2', 'os-release'],
            '/var': ['log', 'www', 'lib', 'cache', 'backups'],
            '/var/log': ['syslog', 'auth.log', 'nginx', 'apache2', 'mysql'],
            '/var/www': ['html'],
            '/var/www/html': ['index.html', 'style.css', 'script.js'],
            '/tmp': ['tmp_file_1', 'session_123'],
            '/usr': ['bin', 'lib', 'share', 'local'],
            '/usr/bin': ['python3', 'bash', 'ls', 'cat', 'grep', 'vim', 'nano', 'wget', 'curl', 'tar', 'zip', 'unzip'],
            '/root': ['.bashrc', '.profile', '.ssh'],
        }
    
    def _get_dir_contents(self, path):
        if path == '~':
            path = f'/home/{self.username}'
        elif path.startswith('~/'):
            path = f'/home/{self.username}/{path[2:]}'
        elif not path.startswith('/'):
            path = f'{self.cwd}/{path}'
        
        path = path.rstrip('/')
        if not path:
            path = '/'
            
        parts = []
        for part in path.split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part and part != '.':
                parts.append(part)
        
        path = '/' + '/'.join(parts) if parts else '/'
        
        return self.filesystem.get(path, None), path
    
    def _path_exists(self, path):
        contents, normalized = self._get_dir_contents(path)
        if contents is not None:
            return True, normalized
        
        parent = '/'.join(normalized.split('/')[:-1]) or '/'
        filename = normalized.split('/')[-1]
        parent_contents, _ = self._get_dir_contents(parent)
        
        if parent_contents and filename in parent_contents:
            return True, normalized
        
        return False, normalized
        
    def connection_made(self, chan):
        self._chan = chan
        
    def shell_requested(self):
        return True
        
    def session_started(self):
        os_banners = {
            'Ubuntu': "\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-20-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\n",
            'Debian': "\r\nDebian GNU/Linux 11 (bullseye)\r\n\r\n * Documentation:  https://www.debian.org/doc/\r\n * Support:        https://www.debian.org/support\r\n\r\n",
            'CentOS': "\r\nCentOS Linux release 7.9.2009 (Core)\r\n\r\n * Documentation:  https://docs.centos.org/\r\n * Support:        https://www.centos.org/\r\n\r\n",
            'Windows': "\r\nMicrosoft Windows Server 2019 Standard\r\n(c) 2019 Microsoft Corporation. All rights reserved.\r\n\r\n",
            'Kali': "\r\nKali GNU/Linux Rolling\r\n\r\n * Documentation:  https://www.kali.org/docs/\r\n * Tools:          https://www.kali.org/tools/\r\n\r\n"
        }
        
        welcome = os_banners.get(self.os_template, os_banners['Ubuntu'])
        welcome += f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {self.client_ip}\r\n"
        
        self._chan.write(welcome)
        self._send_prompt()
        
    def _send_prompt(self):
        display_path = self.cwd
        home = f'/home/{self.username}'
        if self.cwd == home:
            display_path = '~'
        elif self.cwd.startswith(home + '/'):
            display_path = '~' + self.cwd[len(home):]
        
        user_display = f"{self.username}@{self.hostname}"
        if self.sudo_active and self.sudo_user:
            user_display = f"{self.sudo_user}@{self.hostname}"
        
        prompt = f"{user_display}:{display_path}# " if self.sudo_active else f"{user_display}:{display_path}$ "
        self._chan.write(prompt)
        
    def data_received(self, data, datatype):
        if self.in_editor:
            self._handle_editor_input(data)
            return
            
        if self.scp_mode and datatype == asyncssh.EXTENDED_DATA_STDERR:
            self.scp_received += len(data)
            if self.scp_received >= self.scp_file_size:
                self.scp_mode = False
                parent = self.cwd
                if parent in self.filesystem:
                    filename = self.scp_filename.split('/')[-1]
                    if filename not in self.filesystem[parent]:
                        self.filesystem[parent].append(filename)
                self._chan.write(f"\r\n{self.scp_filename} uploaded successfully ({self.scp_file_size} bytes)\r\n")
                self._send_prompt()
            return
            
        command = data.strip()
        
        if not command:
            self._send_prompt()
            return
            
        self.ssh_service.log_event("command", {
            "client_ip": self.client_ip,
            "username": self.username,
            "command": command
        })
        
        response = self.process_command(command)
        
        if not self.in_editor:
            self._chan.write(response)
            
            if command == 'exit' and self.sudo_active:
                self.sudo_active = False
                self.sudo_user = None
                self._send_prompt()
            elif command.lower() in ['exit', 'logout', 'quit']:
                self._chan.exit(0)
            elif command == 'sudo su' or (command.startswith('sudo su ') and '-' not in command):
                self.sudo_active = True
                self.sudo_user = 'root'
                self._send_prompt()
            else:
                self._send_prompt()
        else:
            self._chan.write(response)

    def exec_requested(self, command):
        output = self.process_command(command)
        self._chan.write(output)
        self._send_prompt()

        return True
            
    def process_command(self, cmd: str) -> str:
        cmd = cmd.strip()
        parts = cmd.split()
        
        if not parts:
            return ""
        
        self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        
        if parts[0] == 'sudo':
            return self._handle_sudo(cmd, parts[1:])
        
        command = parts[0]
        
        if command == 'whoami':
            return f"{self.sudo_user if self.sudo_active else self.username}\r\n"
        elif command == 'pwd':
            return f"{self.cwd}\r\n"
        elif command == 'hostname':
            return f"{self.hostname}\r\n"
        elif command == 'id':
            if self.sudo_active:
                return f"uid=0(root) gid=0(root) groups=0(root)\r\n"
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\r\n"
        
        elif command == 'ls':
            target = self.cwd
            show_long = False
            show_all = False
            show_human = False
            
            for arg in parts[1:]:
                if arg.startswith('-'):
                    if 'l' in arg:
                        show_long = True
                    if 'a' in arg:
                        show_all = True
                    if 'h' in arg:
                        show_human = True
                elif not arg.startswith('-'):
                    target = arg
            
            contents, path = self._get_dir_contents(target)
            
            if contents is None:
                return f"ls: cannot access '{target}': No such file or directory\r\n"
            
            if show_long:
                result = f"total {random.randint(20, 100)}\r\n"
                if show_all:
                    result += f"drwxr-xr-x 4 {self.username} {self.username} 4096 Dec 24 10:30 .\r\n"
                    result += f"drwxr-xr-x 3 root  root  4096 Dec 20 15:22 ..\r\n"
                
                for item in contents:
                    if item.startswith('.'):
                        if show_all:
                            is_dir = self.filesystem.get(f"{path}/{item}".rstrip('/'))
                            size = random.randint(100, 9999)
                            if show_human and size > 1024:
                                size_str = f"{size/1024:.1f}K"
                            else:
                                size_str = str(size)
                            if is_dir:
                                result += f"drwxr-xr-x 2 {self.username} {self.username} 4096 Dec 24 10:30 {item}\r\n"
                            else:
                                result += f"-rw-r--r-- 1 {self.username} {self.username} {size_str} Dec 24 10:30 {item}\r\n"
                    else:
                        is_dir = self.filesystem.get(f"{path}/{item}".rstrip('/'))
                        size = random.randint(100, 9999)
                        if show_human and size > 1024:
                            size_str = f"{size/1024:.1f}K"
                        else:
                            size_str = str(size)
                        if is_dir:
                            result += f"drwxr-xr-x 2 {self.username} {self.username} 4096 Dec 24 10:30 {item}\r\n"
                        else:
                            result += f"-rw-r--r-- 1 {self.username} {self.username} {size_str} Dec 24 10:30 {item}\r\n"
                return result
            else:
                items = [i for i in contents if show_all or not i.startswith('.')]
                return '  '.join(items) + "\r\n" if items else "\r\n"
        
        elif command == 'cd':
            if len(parts) == 1:
                self.cwd = f'/home/{self.username}'
                return ""
            
            target = parts[1]
            
            if target == '~':
                self.cwd = f'/home/{self.username}'
                return ""
            elif target == '-':
                return ""
            
            exists, new_path = self._path_exists(target)
            
            if not exists:
                return f"bash: cd: {target}: No such file or directory\r\n"
            
            if new_path in self.filesystem:
                self.cwd = new_path
                self.environment['PWD'] = new_path
                return ""
            else:
                return f"bash: cd: {target}: Not a directory\r\n"
        
        elif command == 'cat':
            if len(parts) < 2:
                return ""
            
            target = parts[1]
            exists, path = self._path_exists(target)
            
            if not exists:
                return f"cat: {target}: No such file or directory\r\n"
            
            if path in self.filesystem:
                return f"cat: {target}: Is a directory\r\n"
            
            filename = path.split('/')[-1]
            
            if filename == 'passwd' or path == '/etc/passwd':
                return f"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
{self.username}:x:1000:1000::/home/{self.username}:/bin/bash
mysql:x:111:118:MySQL Server:/nonexistent:/bin/false
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
\r\n"""
            elif filename == '.bashrc':
                return """# ~/.bashrc: executed by bash(1)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ls='ls --color=auto'
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
\r\n"""
            elif filename == '.profile':
                return """# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
\r\n"""
            elif filename == 'notes.txt':
                return """Important notes:
- Server backup scheduled for tonight at 2 AM
- Remember to update SSL certificates before Jan 1st
- Check database logs for any unusual activity
- Team meeting tomorrow at 10 AM
\r\n"""
            elif filename == 'README.md':
                return """# Project Documentation

## Overview
This is a sample project for demonstration purposes.

## Installation
Run `./setup.sh` to install dependencies.

## Configuration
Edit `config.ini` for custom settings.
\r\n"""
            elif filename == 'config.ini':
                return """[database]
host=localhost
port=3306
username=admin
password=changeme123

[server]
port=8080
debug=false
\r\n"""
            elif filename == 'setup.sh':
                return """#!/bin/bash
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 nginx mysql-server
echo "Installation complete!"
\r\n"""
            elif filename == 'todo.txt':
                return """TODO List:
[ ] Update documentation
[ ] Fix bug in login module
[x] Deploy to production
[ ] Security audit
\r\n"""
            elif filename == 'authorized_keys':
                return """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZy7T... user@hostname
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... admin@server
\r\n"""
            elif filename == 'id_rsa':
                return """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzMxdNB... (fake key)
-----END RSA PRIVATE KEY-----
\r\n"""
            elif filename == 'index.html':
                return """<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Welcome to the server</h1>
</body>
</html>
\r\n"""
            elif filename == 'os-release':
                if self.os_template == 'Ubuntu':
                    return """NAME="Ubuntu"
VERSION="18.04.6 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.6 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
\r\n"""
                elif self.os_template == 'CentOS':
                    return """NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:7"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-7"
CENTOS_MANTISBT_PROJECT_VERSION="7"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="7"
\r\n"""
            else:
                parent_path = path.rsplit('/', 1)[0] or '/'
                if parent_path in self.filesystem:
                    return ""
                return f"cat: {target}: No such file or directory\r\n"
        
        elif command == 'uname':
            if '-a' in parts:
                kernel = "4.15.0-20-generic" if self.os_template == 'Ubuntu' else "3.10.0-1160.el7.x86_64"
                return f"Linux {self.hostname} {kernel} #21-Ubuntu SMP x86_64 GNU/Linux\r\n"
            else:
                return "Linux\r\n"
        
        elif command == 'ps':
            show_all = False
            show_full = False
            show_user = False
            
            for arg in parts[1:]:
                if arg.startswith('-'):
                    if 'a' in arg:
                        show_all = True
                    if 'f' in arg:
                        show_full = True
                    if 'u' in arg:
                        show_user = True
                    if 'aux' in arg:
                        show_all = True
                        show_user = True
                        show_full = True
            
            if show_full:
                header = "UID        PID  PPID  C STIME TTY          TIME CMD\r\n"
                processes = [
                    f"{self.username}     {random.randint(1000, 5000)} {random.randint(1, 500)}  0 {random.randint(10,23)}:{random.randint(10,59)} pts/0    00:00:00 -bash",
                    f"root         {random.randint(100, 1000)}     1  0 Dec24 ?        00:00:00 /usr/sbin/sshd",
                    f"root         {random.randint(100, 1000)}     1  0 Dec24 ?        00:00:00 /usr/sbin/apache2",
                    f"mysql        {random.randint(100, 1000)}     1  0 Dec24 ?        00:00:00 /usr/sbin/mysqld",
                    f"{self.username}     {random.randint(5000, 6000)} {random.randint(1000, 5000)}  0 {datetime.now().strftime('%H:%M')} pts/0    00:00:00 ps -f"
                ]
                return header + "\r\n".join(processes) + "\r\n"
            elif show_all and show_user:
                return f"""USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.3 169692 13004 ?        Ss   Dec24   0:01 /sbin/init
root       456  0.0  0.1  72320  5120 ?        Ss   Dec24   0:00 /usr/sbin/sshd
{self.username}      {random.randint(1000, 5000)}  0.0  0.2  25528 10240 pts/0    Ss+  {datetime.now().strftime('%H:%M')}   0:00 -bash
{self.username}      {random.randint(5000, 6000)}  0.0  0.1  38152  5120 pts/0    R+   {datetime.now().strftime('%H:%M')}   0:00 ps aux
\r\n"""
            elif show_all:
                return f"""  PID TTY          TIME CMD
    1 ?        00:00:01 systemd
    2 ?        00:00:00 kthreadd
  {random.randint(100, 1000)} ?        00:00:00 sshd
  {random.randint(100, 1000)} ?        00:00:00 apache2
  {random.randint(100, 1000)} ?        00:00:00 mysqld
  {random.randint(5000, 6000)} pts/0    00:00:00 ps
\r\n"""
            else:
                return f"""  PID TTY          TIME CMD
  {random.randint(5000, 6000)} pts/0    00:00:00 bash
  {random.randint(6000, 7000)} pts/0    00:00:00 ps
\r\n"""
        
        elif command in ['ifconfig', 'ip']:
            if 'addr' in cmd:
                return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x} brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.{random.randint(10, 250)}/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86388sec preferred_lft 86388sec
    inet6 fe80::20c:29ff:fe{random.randint(0,255):02x}:{random.randint(0,255):02x}{random.randint(0,255):02x}/64 scope link 
       valid_lft forever preferred_lft forever
\r\n"""
            else:
                return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.{random.randint(10, 250)}  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::20c:29ff:fe{random.randint(0,255):02x}:{random.randint(0,255):02x}{random.randint(0,255):02x}  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}  txqueuelen 1000  (Ethernet)
        RX packets {random.randint(1000, 10000)}  bytes {random.randint(1000000, 10000000)} ({random.randint(1, 10)}.{random.randint(0,9)} MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(500, 5000)}  bytes {random.randint(500000, 5000000)} ({random.randint(0, 5)}.{random.randint(0,9)} MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets {random.randint(100, 1000)}  bytes {random.randint(10000, 100000)} ({random.randint(0, 100)}.{random.randint(0,9)} KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(100, 1000)}  bytes {random.randint(10000, 100000)} ({random.randint(0, 100)}.{random.randint(0,9)} KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
\r\n"""
        
        elif command == 'clear':
            return "\033[2J\033[H"
        
        elif command == 'echo':
            output = ' '.join(parts[1:])
            
            for var, value in self.environment.items():
                output = output.replace(f'${var}', value)
                output = output.replace(f'${{{var}}}', value)
            
            if '-e' in parts:
                output = output.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
                parts = [p for p in parts if p != '-e']
            
            if '-n' in parts:
                parts = [p for p in parts if p != '-n']
                return output
            
            return output + "\r\n"
        
        elif command == 'wget':
            if len(parts) < 2:
                return "wget: missing URL\r\nUsage: wget [OPTION]... [URL]...\r\n"
            
            url = parts[1]
            filename = url.split('/')[-1] or 'index.html'
            
            if '-O' in parts:
                idx = parts.index('-O')
                if idx + 1 < len(parts):
                    filename = parts[idx + 1]
            
            if self.cwd in self.filesystem:
                if filename not in self.filesystem[self.cwd]:
                    self.filesystem[self.cwd].append(filename)
            
            file_types = {
                '.tar.gz': 'application/x-gzip',
                '.zip': 'application/zip',
                '.deb': 'application/vnd.debian.binary-package',
                '.py': 'text/x-python',
                '.sh': 'text/x-shellscript'
            }
            
            content_type = 'text/html'
            for ext, ctype in file_types.items():
                if filename.endswith(ext):
                    content_type = ctype
                    break
            
            size = random.randint(1024, 10485760)
            speed = random.randint(100, 10000)
            
            return f"""--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}
Resolving {url.split('/')[2]} ({url.split('/')[2]})... 93.184.216.34
Connecting to {url.split('/')[2]} ({url.split('/')[2]})|93.184.216.34|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: {size} ({size/1024:.1f}K) [{content_type}]
Saving to: '{filename}'

{filename}       {'█' * random.randint(20, 50)}{' ' * random.randint(10, 30)} {random.randint(50, 100)}% {size/1024:.1f}K  {speed}KB/s   in {size/(speed*1024):.1f}s    

{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({speed} KB/s) - '{filename}' saved [{size}]
\r\n"""
        
        elif command == 'curl':
            if len(parts) < 2:
                return "curl: try 'curl --help' or 'curl --manual' for more information\r\n"
            
            url = parts[1]
            show_headers = '-i' in parts or '-I' in parts
            follow = '-L' in parts
            
            if show_headers:
                return f"""HTTP/1.1 200 OK
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: {random.choice(['Mon, 23 Dec 2024 10:30:00 GMT', 'Tue, 15 Nov 2024 14:20:00 GMT'])}
Accept-Ranges: bytes
Content-Length: {random.randint(500, 5000)}
Vary: Accept-Encoding
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>
<h1>Example Domain</h1>
<p>This domain is for use in illustrative examples.</p>
</body>
</html>
\r\n"""
            else:
                return "<html><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>\r\n"
        
        elif command == 'tar':
            if len(parts) < 2:
                return "tar: You must specify one of the '-Acdtrux' options\r\nTry 'tar --help' for more information.\r\n"
            
            operation = parts[1]
            
            if 'x' in operation:
                if len(parts) < 3:
                    return "tar: You must specify a file to extract\r\n"
                
                archive = parts[2]
                return f"""x {archive.split('/')[-1]}
x {archive.split('/')[-1].replace('.tar.gz', '') + '/'}
x {archive.split('/')[-1].replace('.tar.gz', '') + '/file1.txt'}
x {archive.split('/')[-1].replace('.tar.gz', '') + '/file2.py'}
x {archive.split('/')[-1].replace('.tar.gz', '') + '/config.json'}
\r\n"""
            
            elif 'c' in operation:
                if len(parts) < 4:
                    return "tar: You must specify files to archive\r\n"
                
                archive = parts[2]
                files = parts[3:]
                return f"""a {archive.split('/')[-1]}
a {' '.join(files)}
\r\n"""
            
            else:
                return "tar: Invalid option\r\n"
        
        elif command == 'zip':
            if len(parts) < 3:
                return "zip error: Nothing to do! (try: zip -h for help)\r\n"
            
            archive = parts[1]
            files = parts[2:]
            
            return f"""  adding: {files[0] if files else 'file'} (stored 0%)
  adding: {' '.join(files[1:3]) if len(files) > 1 else 'another_file'} (deflated {random.randint(10, 80)}%)
  adding: {' '.join(files[3:]) if len(files) > 3 else 'config.ini'} (deflated {random.randint(20, 90)}%)
\r\n"""
        
        elif command == 'unzip':
            if len(parts) < 2:
                return "unzip:  nothing to do\r\n"
            
            archive = parts[1]
            return f"""Archive:  {archive}
  inflating: extracted_file.txt  
  inflating: document.pdf  
   creating: new_folder/
  inflating: new_folder/config.ini  
\r\n"""
        
        elif command == 'env':
            result = ""
            for var, value in self.environment.items():
                result += f"{var}={value}\r\n"
            return result
        
        elif command == 'export':
            if len(parts) < 2:
                return ""
            
            assignment = parts[1]
            if '=' in assignment:
                var, value = assignment.split('=', 1)
                self.environment[var] = value
            
            return ""
        
        elif command == 'history':
            result = ""
            for i, cmd in enumerate(self.command_history[-20:], 1):
                result += f" {i:4}  {cmd}\r\n"
            return result
        
        elif command in ['source', '.']:
            if len(parts) < 2:
                return f"{command}: filename argument required\r\n"
            
            script = parts[1]
            return f"{command}: sourcing '{script}'...\r\n"
        
        elif command == 'bash' and len(parts) > 1:
            script = parts[1]
            return f"Running {script}...\r\nScript executed successfully.\r\n"
        
        elif command == 'su':
            if len(parts) > 1:
                target_user = parts[1]
                self.sudo_active = True
                self.sudo_user = target_user
                return f"Password: \r\n"
            return "su: must be run from a terminal\r\n"
        
        elif command == 'who':
            return f"""{self.username}   pts/0        {datetime.now().strftime('%Y-%m-%d %H:%M')} ({self.client_ip})
root     tty1         Dec24 10:30
\r\n"""
        
        elif command == 'last':
            return f"""{self.username}   pts/0        {self.client_ip}     {datetime.now().strftime('%a %b %d %H:%M')}   still logged in
root     tty1                          Mon Dec 23 10:30   still logged in
{self.username}   pts/1        192.168.1.50    Mon Dec 23 09:15 - 09:30  (00:15)
reboot   system boot  4.15.0-20-generic Mon Dec 23 09:00   still running

wtmp begins Mon Dec 23 09:00:00 2024
\r\n"""
        
        elif command == 'top':
            current_time = datetime.now().strftime('%H:%M:%S')
            uptime = "5 days, 3:42"
            return f"""top - {current_time} up {uptime},  1 user,  load average: 0.12, 0.34, 0.56
Tasks:  {random.randint(100, 200)} total,   1 running, {random.randint(100, 200)} sleeping,   0 stopped,   0 zombie
%Cpu(s):  {random.uniform(0.5, 5.0):.1f} us,  {random.uniform(0.1, 2.0):.1f} sy,  0.0 ni, {random.uniform(92.0, 98.0):.1f} id,  {random.uniform(0.1, 1.0):.1f} wa,  0.0 hi,  {random.uniform(0.1, 0.5):.1f} si,  0.0 st
MiB Mem :   {random.randint(2000, 16000)}.{random.randint(0,9)} total,   {random.randint(500, 4000)}.{random.randint(0,9)} free,   {random.randint(500, 2000)}.{random.randint(0,9)} used,   {random.randint(500, 2000)}.{random.randint(0,9)} buff/cache
MiB Swap:   {random.randint(1000, 4000)}.{random.randint(0,9)} total,   {random.randint(1000, 4000)}.{random.randint(0,9)} free,    0.0 used.   {random.randint(1000, 4000)}.{random.randint(0,9)} avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  169692  13004  10020 S   0.0   0.3   0:01.23 systemd
    2 root      20   0       0      0      0 S   0.0   0.0   0:00.02 kthreadd
    3 root      20   0       0      0      0 I   0.0   0.0   0:00.41 kworker/0:0
    {random.randint(500, 5000)} {self.username}     20   0   {random.randint(30000, 100000)}  {random.randint(5000, 20000)}  {random.randint(3000, 10000)} S   {random.uniform(0.0, 2.0):.1f}  {random.uniform(0.1, 1.0):.1f}   0:00.{random.randint(10, 59)} bash
\r\n"""
        
        elif command == 'netstat':
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.100:22        192.168.1.76:54321      ESTABLISHED
tcp        0      0 192.168.1.100:22        192.168.1.45:12345      ESTABLISHED
\r\n"""
        
        elif command == 'ss':
            return """Netid State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
tcp   LISTEN     0      128          *:22                *:*  
tcp   LISTEN     0      128          *:80                *:*  
tcp   LISTEN     0      128          *:3306              *:*  
tcp   ESTAB      0      0      192.168.1.100:22    192.168.1.76:54321
tcp   ESTAB      0      0      192.168.1.100:22    192.168.1.45:12345
\r\n"""
        
        elif command == 'df':
            return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       20511356 8234567  11235678  43% /
tmpfs            2048000   12345   2035655   1% /tmp
/dev/sdb1      41278536 1234567  37912345   4% /home
\r\n"""
        
        elif command == 'free':
            return """              total        used        free      shared  buff/cache   available
Mem:        4048000     1234567     1567890       12345     1245543     2567890
Swap:       2097152           0     2097152
\r\n"""
        
        elif command == 'ping':
            if len(parts) < 2:
                return "ping: missing host operand\r\n"
            host = parts[1]
            return f"""PING {host} (93.184.216.34) 56(84) bytes of data.
64 bytes from {host}: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from {host}: icmp_seq=2 ttl=64 time=0.098 ms
64 bytes from {host}: icmp_seq=3 ttl=64 time=0.145 ms
64 bytes from {host}: icmp_seq=4 ttl=64 time=0.132 ms
^C
--- {host} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3002ms
rtt min/avg/max/mdev = 0.098/0.124/0.145/0.018 ms
\r\n"""
        
        elif command == 'which':
            if len(parts) < 2:
                return "which: no command specified\r\n"
            
            cmd = parts[1]
            common_paths = {
                'ls': '/bin/ls',
                'bash': '/bin/bash',
                'python': '/usr/bin/python3',
                'ssh': '/usr/bin/ssh',
                'wget': '/usr/bin/wget',
                'curl': '/usr/bin/curl',
                'tar': '/bin/tar',
                'zip': '/usr/bin/zip',
                'unzip': '/usr/bin/unzip',
                'ps': '/bin/ps',
                'top': '/usr/bin/top'
            }
            
            if cmd in common_paths:
                return f"{common_paths[cmd]}\r\n"
            else:
                return f"which: no {cmd} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)\r\n"
        
        elif command.endswith('.sh'):
            exists, path = self._path_exists(command)
            if exists:
                return f"bash: {command}: Permission denied\r\n"
            else:
                return f"bash: {command}: No such file or directory\r\n"
        
        elif command == 'chmod':
            if len(parts) < 3:
                return "chmod: missing operand\r\nTry 'chmod --help' for more information.\r\n"
            
            mode = parts[1]
            filename = parts[2]
            exists, path = self._path_exists(filename)
            
            if not exists:
                return f"chmod: cannot access '{filename}': No such file or directory\r\n"
            
            if '+x' in mode:
                return f""
            return f""
        
        elif command == 'mkdir':
            if len(parts) < 2:
                return "mkdir: missing operand\r\n"
            
            dirname = parts[1]
            exists, new_path = self._path_exists(dirname)
            
            if exists:
                return f"mkdir: cannot create directory '{dirname}': File exists\r\n"
            
            parent_path = new_path.rsplit('/', 1)[0] or '/'
            dir_name = new_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem:
                self.filesystem[parent_path].append(dir_name)
                self.filesystem[new_path] = []
            else:
                return f"mkdir: cannot create directory '{dirname}': No such file or directory\r\n"
            
            return ""
        
        elif command == 'touch':
            if len(parts) < 2:
                return "touch: missing file operand\r\n"
            
            filename = parts[1]
            exists, file_path = self._path_exists(filename)
            
            if exists:
                return ""
            
            parent_path = file_path.rsplit('/', 1)[0] or '/'
            file_name = file_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem:
                self.filesystem[parent_path].append(file_name)
            else:
                return f"touch: cannot touch '{filename}': No such file or directory\r\n"
            
            return ""
        
        elif command == 'rm':
            if len(parts) < 2:
                return "rm: missing operand\r\n"
            
            target = parts[1]
            exists, file_path = self._path_exists(target)
            
            if not exists:
                return f"rm: cannot remove '{target}': No such file or directory\r\n"
            
            if file_path in self.filesystem and '-r' not in parts:
                return f"rm: cannot remove '{target}': Is a directory\r\n"
            
            parent_path = file_path.rsplit('/', 1)[0] or '/'
            file_name = file_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem and file_name in self.filesystem[parent_path]:
                self.filesystem[parent_path].remove(file_name)
                if file_path in self.filesystem:
                    del self.filesystem[file_path]
            
            return ""
        
        elif command == 'mv':
            if len(parts) < 3:
                return "mv: missing file operand\r\n"
            
            source = parts[1]
            dest = parts[2]
            
            exists_src, src_path = self._path_exists(source)
            if not exists_src:
                return f"mv: cannot stat '{source}': No such file or directory\r\n"
            
            parent_src = src_path.rsplit('/', 1)[0] or '/'
            name_src = src_path.rsplit('/', 1)[1]
            
            exists_dest, dest_path = self._path_exists(dest)
            parent_dest = dest_path.rsplit('/', 1)[0] or '/'
            name_dest = dest_path.rsplit('/', 1)[1]
            
            if parent_src in self.filesystem and name_src in self.filesystem[parent_src]:
                self.filesystem[parent_src].remove(name_src)
                
            if parent_dest in self.filesystem:
                self.filesystem[parent_dest].append(name_dest)
            
            return ""
        
        elif command == 'cp':
            if len(parts) < 3:
                return "cp: missing file operand\r\n"
            
            source = parts[1]
            dest = parts[2]
            
            exists_src, src_path = self._path_exists(source)
            if not exists_src:
                return f"cp: cannot stat '{source}': No such file or directory\r\n"
            
            exists_dest, dest_path = self._path_exists(dest)
            parent_dest = dest_path.rsplit('/', 1)[0] or '/'
            name_dest = dest_path.rsplit('/', 1)[1]
            
            if parent_dest in self.filesystem:
                if name_dest not in self.filesystem[parent_dest]:
                    self.filesystem[parent_dest].append(name_dest)
            
            return ""
        
        elif command == 'find':
            return "./file1.txt\r\n./folder/file2.txt\r\n./.hidden_file\r\n"
        
        elif command == 'grep':
            if len(parts) < 2:
                return ""
            
            pattern = parts[1]
            filename = parts[2] if len(parts) > 2 else None
            
            if filename:
                return f"{filename}: line 1: {pattern} found\r\n{filename}: line 5: {pattern} found again\r\n"
            else:
                return f"grep: {pattern}: No such file or directory\r\n"
        
        else:
            return f"bash: {command}: command not found\r\n"
    
    def _handle_sudo(self, cmd: str, args: list) -> str:
        if not args:
            return "usage: sudo -h | -K | -k | -V\r\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\r\n"
        
        if args[0] == '-l':
            return f"Matching Defaults entries for {self.username} on {self.hostname}:\r\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\r\n\r\nUser {self.username} may run the following commands on {self.hostname}:\r\n    (ALL : ALL) ALL\r\n"
        
        if args[0] == '-u' and len(args) > 2:
            target_user = args[1]
            actual_cmd = ' '.join(args[2:])
            self.sudo_active = True
            self.sudo_user = target_user
            return f"[sudo] password for {self.username}: \r\n"
        
        actual_cmd = ' '.join(args)
        
        sudo_commands = [
            'apt-get', 'apt', 'yum', 'dnf', 'systemctl', 'service',
            'ufw', 'iptables', 'visudo', 'adduser', 'deluser',
            'chown', 'chmod', 'rm -rf /', 'dd if=', 'mkfs',
            'shutdown', 'reboot', 'halt', 'poweroff'
        ]
        
        needs_sudo = any(actual_cmd.startswith(cmd) for cmd in sudo_commands)
        
        if needs_sudo:
            self.sudo_active = True
            self.sudo_user = 'root'
            return f"[sudo] password for {self.username}: \r\n"
        else:
            return self.process_command(actual_cmd)
    
    def scp_requested(self, filename: str, size: int = 0):
        if not self.ssh_service.enable_scp:
            return False
            
        self.scp_mode = True
        self.scp_filename = filename
        self.scp_file_size = size
        self.scp_received = 0
        
        self.ssh_service.log_event("file_upload", {
            "client_ip": self.client_ip,
            "username": self.username,
            "filename": filename,
            "size": size
        })
        
        return True
    
    def _draw_nano_interface(self, filename):
        screen = "\033[2J\033[H"
        
        screen += f"  GNU nano 2.9.3                {filename}                           \r\n"
        screen += "\r\n"
        
        if self.editor_content:
            for line in self.editor_content[:20]:
                screen += line + "\r\n"
            for _ in range(20 - len(self.editor_content)):
                screen += "\r\n"
        else:
            for _ in range(20):
                screen += "\r\n"
        
        screen += "^G Get Help  ^O Write Out ^W Where Is  ^K Cut Text  ^J Justify   ^C Cur Pos\r\n"
        screen += "^X Exit      ^R Read File ^\\ Replace   ^U Uncut Text^T To Spell  ^_ Go To Line"
        
        return screen
    
    def _handle_editor_input(self, data):
        if data == b'\x18':
            self.in_editor = False
            
            parent_path = self.editor_file.rsplit('/', 1)[0] or '/'
            file_name = self.editor_file.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem and file_name not in self.filesystem[parent_path]:
                self.filesystem[parent_path].append(file_name)
            
            self._chan.write("\033[2J\033[H")
            self._send_prompt()
            return
        
        elif data == b'\x03':
            return
        
        elif data == b'\r' or data == b'\n':
            self.editor_content.append('')
            self._chan.write(self._draw_nano_interface(self.editor_file.split('/')[-1]))
            return
        
        elif data == b'\x7f' or data == b'\x08':
            if self.editor_content and len(self.editor_content[-1]) > 0:
                self.editor_content[-1] = self.editor_content[-1][:-1]
            self._chan.write(self._draw_nano_interface(self.editor_file.split('/')[-1]))
            return
        
        else:
            try:
                text = data.decode('utf-8', errors='ignore')
                if text.isprintable() or text == ' ':
                    if not self.editor_content:
                        self.editor_content.append('')
                    self.editor_content[-1] += text
                    self._chan.write(text)
            except:
                pass
            
    def eof_received(self):
        return False
        
    def break_received(self, msec):
        pass