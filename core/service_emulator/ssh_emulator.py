import asyncio
import asyncssh
import json
import random
import os
from datetime import datetime
from pathlib import Path


class SSHService:
    
    def __init__(self, port: int, config: dict, security_layer=None):
        self.port = port
        self.config = config
        self.security = security_layer
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3')
        
        self.security_enabled = True
        if security_layer:
            self.security_enabled = security_layer.enabled

        self.any_auth = config.get('any_auth', True)
        self.brute_force_attempts = config.get('brute_force_attempts', 1)
        self.failed_attempts = {}
        self.username = config.get('username', 'admin')
        
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
        except:
            pass
    
    async def start(self):
        print(f"[SSH] Starting SSH honeypot on port {self.port}")
        print(f"[SSH] Security enabled: {self.security_enabled}")
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

            clean_banner = self.banner.replace('\r', '').replace('\n', ' ').strip()
            server_version = clean_banner.replace('SSH-2.0-', '')
            
            print(f"[SSH] Creating server on port {self.port}...")
            print(f"[SSH] Using banner: {clean_banner}")
            
            self.server = await asyncssh.create_server(
                lambda: SSHServer(self),
                '0.0.0.0',
                self.port,
                server_host_keys=[self.host_key],
                server_version=server_version,
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

    async def cleanup_failed_attempts(self):
        import time
        while self.is_running:
            await asyncio.sleep(300)  # 5 min
            
            current_time = time.time()
            to_remove = []
            
            for ip, data in self.failed_attempts.items():
                if hasattr(data, 'last_attempt'):
                    if current_time - data.last_attempt > 3600:
                        to_remove.append(ip)
            
            for ip in to_remove:
                del self.failed_attempts[ip]


class SSHServer(asyncssh.SSHServer):
    
    def __init__(self, ssh_service):
        self.ssh_service = ssh_service
        self.connection_closed = False
        
    def connection_made(self, conn):
        self.conn = conn
        client_ip = conn.get_extra_info('peername')[0]
        
        if self.ssh_service.security and self.ssh_service.security_enabled:
            if not self.ssh_service.security.is_ip_allowed(client_ip):
                print(f"[SECURITY] Blocked connection from {client_ip} - aborting")
                self.ssh_service.log_event("blocked_connection", {
                    "client_ip": client_ip,
                    "reason": "IP blocked (rate limit, temp ban, or perm ban)"
                })
                self.connection_closed = True
                conn.abort()
                return
        
        if self.ssh_service.security and self.ssh_service.security_enabled:
            self.ssh_service.security.record_connection(client_ip)
        
        self.ssh_service.log_event("connection", {"client_ip": client_ip})
    
    def connection_lost(self, exc):
        """Called when connection is lost or closed"""
        if hasattr(self, 'conn'):
            client_ip = self.conn.get_extra_info('peername')[0]
            if client_ip in self.ssh_service.failed_attempts:
                del self.ssh_service.failed_attempts[client_ip]
                print(f"[SSH] Cleared failed_attempts data for {client_ip}")
    
    def validate_password(self, username, password):
        client_ip = self.conn.get_extra_info('peername')[0]
        self.username = username
        
        security_enabled = self.ssh_service.security_enabled
        
        if security_enabled and self.ssh_service.security:
            if not self.ssh_service.security.is_ip_allowed(client_ip):
                print(f"[SECURITY] Blocked login attempt from blocked IP: {client_ip}")
                return False
        
        if client_ip not in self.ssh_service.failed_attempts:
            self.ssh_service.failed_attempts[client_ip] = {
                'count': 0,
                'attempts': []
            }
        
        ip_data = self.ssh_service.failed_attempts[client_ip]
        current_attempt = (username, password)
        
        if self.ssh_service.any_auth:
            ip_data['count'] += 1
            
            if ip_data['count'] < self.ssh_service.brute_force_attempts:
                ip_data['attempts'].append(current_attempt)
                
                print(f"[SSH] Brute-force test: failing attempt {ip_data['count']}/{self.ssh_service.brute_force_attempts} for {client_ip}")
                
                if security_enabled and self.ssh_service.security:
                    self.ssh_service.security.record_failed_attempt(client_ip)
                
                self.ssh_service.log_event("login_attempt", {
                    "client_ip": client_ip,
                    "username": username,
                    "password": password,
                    "success": False,
                    "valid_credentials": False,
                    "any_auth_mode": self.ssh_service.any_auth,
                    "security_enabled": security_enabled,
                    "brute_force_test": True,
                    "attempt_number": ip_data['count']
                })
                return False
            
            if current_attempt in ip_data['attempts']:
                print(f"[SSH] Brute-force test: rejecting identical credentials ({username}/{password}) for {client_ip}")
                ip_data['count'] += 1
                
                if security_enabled and self.ssh_service.security:
                    self.ssh_service.security.record_failed_attempt(client_ip)
                
                self.ssh_service.log_event("login_attempt", {
                    "client_ip": client_ip,
                    "username": username,
                    "password": password,
                    "success": False,
                    "valid_credentials": False,
                    "any_auth_mode": self.ssh_service.any_auth,
                    "security_enabled": security_enabled,
                    "brute_force_test": True,
                    "identical_credentials": True,
                    "attempt_number": ip_data['count']
                })
                return False
            
            print(f"[SSH] Brute-force test: success on attempt {ip_data['count']} for {client_ip}")
            
            ip_data['count'] = 0
            ip_data['attempts'] = []
                
            self.ssh_service.log_event("login_attempt", {
                "client_ip": client_ip,
                "username": username,
                "password": password,
                "success": True,
                "valid_credentials": True,
                "any_auth_mode": self.ssh_service.any_auth,
                "security_enabled": security_enabled,
                "brute_force_test": True,
                "attempt_number": ip_data['count']
            })
            return True
        else:
            is_valid = username in self.ssh_service.users and self.ssh_service.users[username] == password
            
            if security_enabled and self.ssh_service.security:
                if not is_valid:
                    self.ssh_service.security.record_failed_attempt(client_ip)
                    print(f"[SECURITY] Failed login attempt from {client_ip}")
                    
                    if not self.ssh_service.security.check_rate_limit(client_ip):
                        print(f"[SECURITY] Blocking IP {client_ip} for too many failed attempts")
                        self.ssh_service.security.temp_block_ip(client_ip)
                        return False
            
            self.ssh_service.log_event("login_attempt", {
                "client_ip": client_ip,
                "username": username,
                "password": password,
                "success": is_valid,
                "valid_credentials": is_valid,
                "any_auth_mode": self.ssh_service.any_auth,
                "security_enabled": security_enabled
            })
            
            return is_valid
        
    def begin_auth(self, username):
        if hasattr(self, 'connection_closed') and self.connection_closed:
            return False
        return True
        
    def password_auth_supported(self):
        return True
        
    def public_key_auth_supported(self):
        return True
    
    def session_requested(self):
        client_ip = self.conn.get_extra_info('peername')[0]
        username = getattr(self, 'username', self.ssh_service.username)
        hostname = self.ssh_service.hostname
        
        print(f"[SSH] Session requested by {username}@{client_ip}")
        
        return SSHServerSession(self.ssh_service, username, client_ip, hostname)


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
        
        self.session_start_time = datetime.now()
        self.command_timeout = ssh_service.config.get('command_timeout', 30)
        self.max_session_time = ssh_service.config.get('max_session_time', 3600)

        self.vim_command_mode = False
        self.vim_command_buffer = ''
        self.save_prompt = False
        self.nano_cursor_line = 0
        self.nano_cursor_col = 0
        self.cut_buffer = []
    
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
            
        if self.vim_command_mode:
            self._handle_editor_input(data)
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

        cmd_lower = command.lower()
        if cmd_lower in ['exit', 'logout', 'quit']:
            if self.sudo_active:
                self.sudo_active = False
                self.sudo_user = None
                self._chan.write("\r\n")
                self._send_prompt()
            else:
                self._chan.write("\r\n")
                self._chan.exit(0)
            return
        
        response = self.process_command(command)
        
        if not self.in_editor:
            self._chan.write(response)
            
            if command == 'sudo su' or (command.startswith('sudo su ') and '-' not in command):
                self.sudo_active = True
                self.sudo_user = 'root'
                self._send_prompt()
            else:
                self._send_prompt()
        else:
            self._chan.write(response)
            
    def process_command(self, cmd: str) -> str:
        cmd = cmd.strip()
        parts = cmd.split()
        
        if not parts:
            return ""
        
        if cmd.lower() in ['exit', 'logout', 'quit']:
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
            elif filename == 'notes.txt':
                return """Important notes:
- Server backup scheduled for tonight at 2 AM
- Remember to update SSL certificates before Jan 1st
- Check database logs for any unusual activity
\r\n"""
            else:
                return f"Sample content of {filename}\r\n"
        
        elif command == 'grep':
            if len(parts) < 3:
                return "Usage: grep [OPTION]... PATTERN [FILE]...\r\n"
            pattern = parts[1]
            target = ' '.join(parts[2:])
            return f"grep: {target}: No such file or directory\r\n"
        
        elif command == 'find':
            if len(parts) == 1:
                find_path = self.cwd
            else:
                find_path = parts[1]
            
            exists, path = self._path_exists(find_path)
            if not exists:
                return f"find: '{find_path}': No such file or directory\r\n"
            
            result = f"{path}\r\n"
            contents, _ = self._get_dir_contents(path)
            if contents:
                for item in contents[:5]:
                    result += f"{path}/{item}\r\n"
            return result
        
        elif command in ['vim', 'vi']:
            if len(parts) < 2:
                return "E325: ATTENTION: no file specified\r\n"
            self.editor_file = parts[1]
            self.editor_type = 'vim'
            self.in_editor = True
            self.vim_command_mode = False
            exists, _ = self._path_exists(self.editor_file)
            if exists:
                self.editor_content = [f"Sample content of {self.editor_file}"]
            else:
                self.editor_content = []
            return self._render_vim()
        
        elif command == 'nano':
            if len(parts) < 2:
                return "nano: missing file operand\r\n"
            self.editor_file = parts[1]
            self.editor_type = 'nano'
            self.in_editor = True
            self.nano_cursor_line = 0
            self.nano_cursor_col = 0
            exists, _ = self._path_exists(self.editor_file)
            if exists:
                self.editor_content = [f"Sample content of {self.editor_file}"]
            else:
                self.editor_content = []
            return self._render_nano()
        
        elif command == 'wget':
            if len(parts) < 2:
                return "wget: missing URL\r\n"
            url = parts[1]
            filename = url.split('/')[-1] or 'index.html'
            return f"""--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}
Resolving host... ({random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)})
Connecting to host... connected.
HTTP request sent, awaiting response... 200 OK
Length: {random.randint(1000, 99999)} ({random.randint(10, 99)}K) [text/html]
Saving to: '{filename}'

{filename}              100%[===================>]  {random.randint(10, 99)}.{random.randint(10,99)}K  --.-KB/s    in 0.{random.randint(1,9)}s

{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({random.randint(100, 999)} KB/s) - '{filename}' saved [{random.randint(10000, 99999)}/{random.randint(10000, 99999)}]

\r\n"""
        
        elif command == 'curl':
            if len(parts) < 2:
                return "curl: try 'curl --help' for more information\r\n"
            url = parts[1]
            return f"""<!DOCTYPE html>
<html>
<head><title>Sample Page</title></head>
<body><h1>Welcome</h1><p>This is a sample response from {url}</p></body>
</html>
\r\n"""
        
        elif command == 'ps':
            return f"""  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 ps
\r\n"""
        
        elif command == 'top':
            return """top - 10:30:45 up 5 days,  3:21,  1 user,  load average: 0.12, 0.18, 0.15
Tasks:  95 total,   1 running,  94 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.2 id,  0.3 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   2048.0 total,    456.2 free,    821.5 used,    770.3 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.   1142.8 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 1234 root      20   0  162944   5632   4096 S   1.3   0.3   0:02.45 sshd
\r\n"""
        
        elif command == 'df':
            show_human = '-h' in parts
            if show_human:
                return """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G   12G  7.2G  63% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G   45G   51G  47% /home
\r\n"""
            else:
                return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       20971520 12582912   7549952  63% /
tmpfs            2097152        0   2097152   0% /dev/shm
/dev/sda2      104857600 47185920  52428800  47% /home
\r\n"""
        
        elif command == 'free':
            show_human = '-h' in parts
            if show_human:
                return """              total        used        free      shared  buff/cache   available
Mem:          2.0Gi       800Mi       450Mi        12Mi       770Mi       1.1Gi
Swap:         1.0Gi          0B       1.0Gi
\r\n"""
            else:
                return """              total        used        free      shared  buff/cache   available
Mem:        2097152      819200      460800       12288      788352     1167360
Swap:       1048576           0     1048576
\r\n"""
        
        elif command == 'uname':
            if '-a' in parts:
                kernel = "4.15.0-20-generic" if self.os_template == 'Ubuntu' else "3.10.0-1160.el7.x86_64"
                return f"Linux {self.hostname} {kernel} #21-Ubuntu SMP x86_64 GNU/Linux\r\n"
            else:
                return "Linux\r\n"
        
        elif command == 'uptime':
            days = random.randint(1, 30)
            hours = random.randint(0, 23)
            minutes = random.randint(0, 59)
            return f" 10:30:45 up {days} days, {hours}:{minutes:02d},  1 user,  load average: 0.12, 0.18, 0.15\r\n"
        
        elif command == 'date':
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y") + "\r\n"
        
        elif command == 'ifconfig' or command == 'ip':
            return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
        RX packets 123456  bytes 98765432 (98.7 MB)
        TX packets 67890  bytes 12345678 (12.3 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
\r\n"""
        
        elif command == 'netstat':
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.100:22        """ + self.client_ip + """:12345      ESTABLISHED
\r\n"""
        
        elif command == 'history':
            result = ""
            for i, hist_cmd in enumerate(self.command_history[-20:], 1):
                result += f"  {i}  {hist_cmd}\r\n"
            return result
        
        elif command == 'env' or command == 'printenv':
            result = ""
            for key, value in self.environment.items():
                result += f"{key}={value}\r\n"
            return result
        
        elif command == 'export':
            if len(parts) < 2:
                return self.process_command('env')
            var_assign = ' '.join(parts[1:])
            if '=' in var_assign:
                var_name, var_value = var_assign.split('=', 1)
                self.environment[var_name] = var_value.strip('"').strip("'")
            return ""
        
        elif command == 'chmod':
            if len(parts) < 3:
                return "chmod: missing operand\r\n"
            return ""
        
        elif command == 'chown':
            if len(parts) < 3:
                return "chown: missing operand\r\n"
            return ""
        
        elif command == 'mkdir':
            if len(parts) < 2:
                return "mkdir: missing operand\r\n"
            dirname = parts[1]
            return ""
        
        elif command == 'rmdir':
            if len(parts) < 2:
                return "rmdir: missing operand\r\n"
            return ""
        
        elif command == 'rm':
            if len(parts) < 2:
                return "rm: missing operand\r\n"
            return ""
        
        elif command == 'cp':
            if len(parts) < 3:
                return "cp: missing destination file operand\r\n"
            return ""
        
        elif command == 'mv':
            if len(parts) < 3:
                return "mv: missing destination file operand\r\n"
            return ""
        
        elif command == 'touch':
            if len(parts) < 2:
                return "touch: missing file operand\r\n"
            return ""
        
        elif command == 'tail':
            if len(parts) < 2:
                return "tail: missing file operand\r\n"
            target = parts[1]
            return f"Sample tail output of {target}\r\nLine 1\r\nLine 2\r\nLine 3\r\n"
        
        elif command == 'head':
            if len(parts) < 2:
                return "head: missing file operand\r\n"
            target = parts[1]
            return f"Sample head output of {target}\r\nLine 1\r\nLine 2\r\nLine 3\r\n"
        
        elif command == 'tar':
            if len(parts) < 2:
                return "tar: missing operand\r\n"
            return ""
        
        elif command == 'zip' or command == 'unzip':
            if len(parts) < 2:
                return f"{command}: missing operand\r\n"
            return ""
        
        elif command == 'systemctl':
            if len(parts) < 2:
                return "systemctl: missing operand\r\n"
            action = parts[1]
            service = parts[2] if len(parts) > 2 else "unknown"
            if action == 'status':
                return f"""● {service}.service - {service.capitalize()} Service
   Loaded: loaded (/lib/systemd/system/{service}.service; enabled)
   Active: active (running) since {datetime.now().strftime('%a %Y-%m-%d %H:%M:%S %Z')}
\r\n"""
            return ""
        
        elif command == 'service':
            if len(parts) < 2:
                return "service: missing service name\r\n"
            return ""
        
        elif command == 'clear':
            return "\033[2J\033[H"
        
        elif command == 'echo':
            output = ' '.join(parts[1:])
            for var, value in self.environment.items():
                output = output.replace(f'${var}', value)
                output = output.replace(f'${{{var}}}', value)
            if '-n' in parts:
                parts = [p for p in parts if p != '-n']
                return output
            return output + "\r\n"
        
        elif command == 'man':
            if len(parts) < 2:
                return "What manual page do you want?\r\n"
            return f"Manual page for {parts[1]} - No manual entry for {parts[1]}\r\n"
        
        elif command == 'which':
            if len(parts) < 2:
                return ""
            prog = parts[1]
            return f"/usr/bin/{prog}\r\n"
        
        elif command == 'locate':
            if len(parts) < 2:
                return "locate: no pattern to search for specified\r\n"
            pattern = parts[1]
            return f"/usr/bin/{pattern}\r\n/home/{self.username}/{pattern}\r\n"
        
        elif command == 'du':
            show_human = '-h' in parts
            if show_human:
                return f"4.0K\t./Documents\r\n8.0K\t./Downloads\r\n12K\t.\r\n"
            else:
                return f"4\t./Documents\r\n8\t./Downloads\r\n12\t.\r\n"
        
        elif command == 'w' or command == 'who':
            return f""" 10:30:45 up 5 days,  3:21,  1 user,  load average: 0.12, 0.18, 0.15
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{self.username}     pts/0    {self.client_ip}   10:28    0.00s  0.04s  0.00s w
\r\n"""
        
        elif command == 'last':
            return f"""{self.username}     pts/0        {self.client_ip}   {datetime.now().strftime('%a %b %d %H:%M')}   still logged in
{self.username}     pts/0        {self.client_ip}   {datetime.now().strftime('%a %b %d %H:%M')} - {datetime.now().strftime('%H:%M')}  (00:15)

wtmp begins {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}
\r\n"""
        
        elif command == 'reboot' or command == 'shutdown':
            if not self.sudo_active:
                return f"{command}: Need to be root\r\n"
            return f"System going down for reboot NOW!\r\n"
        
        elif command == 'python' or command == 'python3':
            return "Python 3.8.10 (default, Nov 26 2021, 20:14:08)\r\n[GCC 9.3.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>>\r\n"
        
        else:
            return f"bash: {command}: command not found\r\n"
    
    def _handle_sudo(self, cmd: str, args: list) -> str:
        if not args:
            return "usage: sudo -h | -K | -k | -V\r\n"
        
        actual_cmd = ' '.join(args)
        
        if actual_cmd == 'su':
            self.sudo_active = True
            self.sudo_user = 'root'
            return f"[sudo] password for {self.username}: \r\n"
        else:
            return self.process_command(actual_cmd)
    
    def _render_vim(self):
        output = "\033[2J\033[H"
        term_height = 24
        term_width = 80
        
        for i in range(term_height - 2):
            if i < len(self.editor_content):
                line = self.editor_content[i]
                output += f"{line[:term_width]}\r\n"
            else:
                output += "~\r\n"
        
        file_info = f'"{self.editor_file}" [New File]'
        output += f"\033[7m{file_info.ljust(term_width)}\033[0m\r\n"
        output += "\033[1;1H"
        
        return output
    
    def _render_nano(self):
        output = "\033[2J\033[H"
        output += f"  GNU nano 4.8               {self.editor_file}\r\n\r\n"
        
        for line in self.editor_content:
            output += f"{line}\r\n"
        
        output += "\r\n" * (20 - len(self.editor_content))
        output += "^G Get Help  ^O Write Out ^W Where Is  ^K Cut Text  ^J Justify\r\n"
        output += "^X Exit      ^R Read File ^\ Replace   ^U Paste Text^T To Spell\r\n"
        
        return output
    
    def _handle_editor_input(self, data):
        if self.editor_type == 'vim':
            if data == '\x1b':
                self.vim_command_mode = True
                self.vim_command_buffer = ''
            elif self.vim_command_mode:
                if data == ':':
                    self.vim_command_buffer = ':'
                    self._chan.write("\r\n:")
                elif data == '\r' and self.vim_command_buffer:
                    if self.vim_command_buffer in [':q', ':q!', ':wq', ':x']:
                        self.in_editor = False
                        self.vim_command_mode = False
                        self._chan.write("\r\n")
                        self._send_prompt()
                    elif self.vim_command_buffer == ':w':
                        self._chan.write(f'\r\n"{self.editor_file}" [New] 0L, 0C written\r\n')
                        self._chan.write(self._render_vim())
                    self.vim_command_buffer = ''
                else:
                    self.vim_command_buffer += data
        
        elif self.editor_type == 'nano':
            if data == '\x18':
                self.in_editor = False
                self._chan.write("\r\n")
                self._send_prompt()
    
    def eof_received(self):
        return False
        
    def break_received(self, msec):
        return False
