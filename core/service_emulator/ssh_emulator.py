import asyncio
import asyncssh
import json
import random
from datetime import datetime
from pathlib import Path

class SSHService:
    
    def __init__(self, port: int, config: dict):
        self.port = port
        self.config = config
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3')
        
        self.any_auth = config.get('any_auth', True)
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
        
    def connection_made(self, conn):
        self.conn = conn
        client_ip = conn.get_extra_info('peername')[0]
        self.ssh_service.log_event("connection", {"client_ip": client_ip})
        
    def connection_lost(self, exc):
        if hasattr(self, 'conn'):
            client_ip = self.conn.get_extra_info('peername')[0]
            self.ssh_service.log_event("disconnection", {"client_ip": client_ip})
        
    def begin_auth(self, username):
        return True
        
    def password_auth_supported(self):
        return True
        
    def public_key_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        client_ip = self.conn.get_extra_info('peername')[0]
        is_valid = username in self.ssh_service.users and self.ssh_service.users[username] == password
        
        # any_auth=True: accept any password (honeypot), any_auth=False: validate credentials
        accept = True if self.ssh_service.any_auth else is_valid
        
        self.ssh_service.log_event("login_attempt", {
            "client_ip": client_ip,
            "username": username,
            "password": password,
            "success": accept,
            "valid_credentials": is_valid,
            "any_auth_mode": self.ssh_service.any_auth
        })
        
        return accept
        
    def validate_public_key(self, username, key):
        client_ip = self.conn.get_extra_info('peername')[0]
        self.ssh_service.log_event("login_attempt", {
            "client_ip": client_ip,
            "username": username,
            "auth_method": "publickey",
            "success": True
        })
        return True
        
    def session_requested(self):
        client_ip = self.conn.get_extra_info('peername')[0]
        username = self.ssh_service.username
        return SSHServerSession(self.ssh_service, username, client_ip, self.ssh_service.hostname)


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
    
    def _create_filesystem(self):
        return {
            '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
            '/home': [self.username, 'ubuntu'],
            f'/home/{self.username}': ['Documents', 'Downloads', 'Pictures', 'Videos', 'Music', 'Desktop', '.bashrc', '.profile', '.ssh'],
            f'/home/{self.username}/Documents': ['notes.txt', 'report.pdf', 'project'],
            f'/home/{self.username}/Documents/project': ['README.md', 'config.ini'],
            f'/home/{self.username}/Downloads': ['setup.sh', 'data.zip', 'installer.deb'],
            f'/home/{self.username}/Pictures': ['photo1.jpg', 'photo2.png'],
            f'/home/{self.username}/Videos': ['video.mp4'],
            f'/home/{self.username}/Music': ['song.mp3'],
            f'/home/{self.username}/Desktop': ['work', 'personal'],
            f'/home/{self.username}/Desktop/work': ['project.doc'],
            f'/home/{self.username}/Desktop/personal': ['todo.txt'],
            f'/home/{self.username}/.ssh': ['authorized_keys', 'known_hosts'],
            '/etc': ['passwd', 'shadow', 'hosts', 'hostname', 'network', 'ssh', 'cron.d', 'nginx', 'apache2'],
            '/var': ['log', 'www', 'lib', 'cache'],
            '/var/log': ['syslog', 'auth.log', 'nginx', 'apache2'],
            '/var/www': ['html'],
            '/var/www/html': ['index.html', 'style.css'],
            '/tmp': ['tmp_file_1', 'session_123'],
            '/usr': ['bin', 'lib', 'share', 'local'],
            '/usr/bin': ['python3', 'bash', 'ls', 'cat', 'grep', 'vim', 'nano'],
        }
    
    def _get_dir_contents(self, path):
        if path == '~':
            path = f'/home/{self.username}'
        elif path.startswith('~/'):
            path = f'/home/{self.username}/{path[2:]}'
        elif not path.startswith('/'):
            path = f'{self.cwd}/{path}'
        
        # Remove trailing slash
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
        
        # Verifica se é um arquivo dentro de um diretório
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
        # Banners baseados no OS Template
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
        # Mostra ~ se estiver em home, senão mostra path
        display_path = self.cwd
        home = f'/home/{self.username}'
        if self.cwd == home:
            display_path = '~'
        elif self.cwd.startswith(home + '/'):
            display_path = '~' + self.cwd[len(home):]
        
        self._chan.write(f"{self.username}@{self.hostname}:{display_path}$ ")
        
    def data_received(self, data, datatype):
        # Se está no editor, processa input do editor
        if self.in_editor:
            self._handle_editor_input(data)
            return
            
        # Processa comando normal
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
        
        # Só envia resposta e prompt se não entrou no modo editor
        if not self.in_editor:
            self._chan.write(response)
            
            if command.lower() in ['exit', 'logout', 'quit']:
                self._chan.exit(0)
            else:
                self._send_prompt()
        else:
            # Se entrou no editor, envia apenas a interface (response já contém)
            self._chan.write(response)
            
    def process_command(self, cmd: str) -> str:
        """Simula comandos Linux com sistema de arquivos virtual"""
        cmd = cmd.strip()
        parts = cmd.split()
        
        if not parts:
            return ""
        
        command = parts[0]
        
        # Comandos básicos
        if command == 'whoami':
            return f"{self.username}\r\n"
        elif command == 'pwd':
            return f"{self.cwd}\r\n"
        elif command == 'hostname':
            return f"{self.hostname}\r\n"
        elif command == 'id':
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\r\n"
        
        # ls - Lista diretórios
        elif command == 'ls':
            target = self.cwd
            show_long = False
            show_all = False
            
            # Parse argumentos
            for arg in parts[1:]:
                if arg.startswith('-'):
                    if 'l' in arg:
                        show_long = True
                    if 'a' in arg:
                        show_all = True
                elif not arg.startswith('-'):
                    target = arg
            
            contents, path = self._get_dir_contents(target)
            
            if contents is None:
                return f"ls: cannot access '{target}': No such file or directory\r\n"
            
            if show_long:
                result = "total 32\r\n"
                if show_all:
                    result += f"drwxr-xr-x 4 {self.username} {self.username} 4096 Dec 24 10:30 .\r\n"
                    result += f"drwxr-xr-x 3 root  root  4096 Dec 20 15:22 ..\r\n"
                
                for item in contents:
                    if item.startswith('.'):
                        if show_all:
                            result += f"-rw-r--r-- 1 {self.username} {self.username}  220 Dec 20 15:22 {item}\r\n"
                    else:
                        # Verifica se é diretório
                        is_dir = self.filesystem.get(f"{path}/{item}".rstrip('/'))
                        if is_dir:
                            result += f"drwxr-xr-x 2 {self.username} {self.username} 4096 Dec 24 10:30 {item}\r\n"
                        else:
                            result += f"-rw-r--r-- 1 {self.username} {self.username} {random.randint(100, 9999)} Dec 24 10:30 {item}\r\n"
                return result
            else:
                items = [i for i in contents if show_all or not i.startswith('.')]
                return '  '.join(items) + "\r\n" if items else "\r\n"
        
        # cd - Muda diretório
        elif command == 'cd':
            if len(parts) == 1:
                self.cwd = f'/home/{self.username}'
                return ""
            
            target = parts[1]
            
            # Casos especiais
            if target == '~':
                self.cwd = f'/home/{self.username}'
                return ""
            elif target == '-':
                # cd - volta ao diretório anterior (não implementado)
                return ""
            
            exists, new_path = self._path_exists(target)
            
            if not exists:
                return f"bash: cd: {target}: No such file or directory\r\n"
            
            # Verifica se é diretório (existe no filesystem)
            if new_path in self.filesystem:
                self.cwd = new_path
                return ""
            else:
                # É um arquivo, não um diretório
                return f"bash: cd: {target}: Not a directory\r\n"
        
        # cat - Lê arquivos
        elif command == 'cat':
            if len(parts) < 2:
                return ""
            
            target = parts[1]
            exists, path = self._path_exists(target)
            
            if not exists:
                return f"cat: {target}: No such file or directory\r\n"
            
            # Verifica se é diretório
            if path in self.filesystem:
                return f"cat: {target}: Is a directory\r\n"
            
            # Conteúdo de arquivos específicos
            filename = path.split('/')[-1]
            
            # Arquivos de sistema
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
\r\n"""
            elif filename == '.profile':
                return """# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
\r\n"""
            
            # Arquivos do usuário com conteúdo específico
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
\r\n"""
            elif filename == 'known_hosts':
                return """192.168.1.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7...
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
            elif filename == 'style.css':
                return """body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
}
h1 { color: #333; }
\r\n"""
            
            # Arquivos criados pelo usuário - retorna vazio
            else:
                # Verifica se foi criado na sessão (não tem conteúdo pré-definido)
                parent_path = path.rsplit('/', 1)[0] or '/'
                if parent_path in self.filesystem:
                    # Arquivo existe mas não tem conteúdo definido
                    return ""
                return f"cat: {target}: No such file or directory\r\n"
        
        # uname
        elif command == 'uname':
            if '-a' in parts:
                return f"Linux {self.hostname} 4.15.0-20-generic #21-Ubuntu SMP x86_64 GNU/Linux\r\n"
            else:
                return "Linux\r\n"
        
        # ps
        elif command == 'ps':
            return f"""  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 ps
\r\n"""
        
        # ifconfig / ip
        elif command in ['ifconfig', 'ip']:
            return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.{random.randint(10, 250)}  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
\r\n"""
        
        # clear
        elif command == 'clear':
            return "\033[2J\033[H"
        
        # echo
        elif command == 'echo':
            return ' '.join(parts[1:]) + "\r\n"
        
        # wget / curl - Download simulation
        elif command == 'wget':
            if len(parts) < 2:
                return "wget: missing URL\r\n"
            url = parts[1]
            filename = url.split('/')[-1] or 'index.html'
            
            # Adiciona arquivo ao diretório atual
            if self.cwd in self.filesystem:
                if filename not in self.filesystem[self.cwd]:
                    self.filesystem[self.cwd].append(filename)
            
            return f"""--2025-12-24 {datetime.now().strftime('%H:%M:%S')}--  {url}
Resolving host... 93.184.216.34
Connecting to host... connected.
HTTP request sent, awaiting response... 200 OK
Length: {random.randint(1000, 50000)} ({random.randint(10, 100)}K)
Saving to: '{filename}'

{filename}    100%[===================>]  {random.randint(10, 100)}K  --.-KB/s    in 0.001s

2025-12-24 {datetime.now().strftime('%H:%M:%S')} ({random.randint(50, 200)} MB/s) - '{filename}' saved
\r\n"""
        
        elif command == 'curl':
            if len(parts) < 2:
                return "curl: no URL specified\r\n"
            return f"<html><body><h1>Sample HTML content</h1></body></html>\r\n"
        
        # mkdir
        elif command == 'mkdir':
            if len(parts) < 2:
                return "mkdir: missing operand\r\n"
            
            dirname = parts[1]
            exists, new_path = self._path_exists(dirname)
            
            if exists:
                return f"mkdir: cannot create directory '{dirname}': File exists\r\n"
            
            # Adiciona ao filesystem
            parent_path = new_path.rsplit('/', 1)[0] or '/'
            dir_name = new_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem:
                self.filesystem[parent_path].append(dir_name)
                self.filesystem[new_path] = []
            else:
                return f"mkdir: cannot create directory '{dirname}': No such file or directory\r\n"
            
            return ""
        
        # touch
        elif command == 'touch':
            if len(parts) < 2:
                return "touch: missing file operand\r\n"
            
            filename = parts[1]
            exists, file_path = self._path_exists(filename)
            
            if exists:
                # Arquivo já existe, apenas "atualiza timestamp"
                return ""
            
            # Cria arquivo novo
            parent_path = file_path.rsplit('/', 1)[0] or '/'
            file_name = file_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem:
                self.filesystem[parent_path].append(file_name)
            else:
                return f"touch: cannot touch '{filename}': No such file or directory\r\n"
            
            return ""
        
        # rm - Remove arquivos
        elif command == 'rm':
            if len(parts) < 2:
                return "rm: missing operand\r\n"
            
            target = parts[1]
            exists, file_path = self._path_exists(target)
            
            if not exists:
                return f"rm: cannot remove '{target}': No such file or directory\r\n"
            
            # Verifica se é diretório
            if file_path in self.filesystem and '-r' not in parts:
                return f"rm: cannot remove '{target}': Is a directory\r\n"
            
            # Remove do filesystem
            parent_path = file_path.rsplit('/', 1)[0] or '/'
            file_name = file_path.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem and file_name in self.filesystem[parent_path]:
                self.filesystem[parent_path].remove(file_name)
                # Se for diretório, remove também
                if file_path in self.filesystem:
                    del self.filesystem[file_path]
            
            return ""
        
        # mv - Move/renomeia arquivos
        elif command == 'mv':
            if len(parts) < 3:
                return "mv: missing file operand\r\n"
            
            source = parts[1]
            dest = parts[2]
            
            exists_src, src_path = self._path_exists(source)
            if not exists_src:
                return f"mv: cannot stat '{source}': No such file or directory\r\n"
            
            # Remove source
            parent_src = src_path.rsplit('/', 1)[0] or '/'
            name_src = src_path.rsplit('/', 1)[1]
            
            # Adiciona dest
            exists_dest, dest_path = self._path_exists(dest)
            parent_dest = dest_path.rsplit('/', 1)[0] or '/'
            name_dest = dest_path.rsplit('/', 1)[1]
            
            if parent_src in self.filesystem and name_src in self.filesystem[parent_src]:
                self.filesystem[parent_src].remove(name_src)
                
            if parent_dest in self.filesystem:
                self.filesystem[parent_dest].append(name_dest)
            
            return ""
        
        # cp - Copia arquivos
        elif command == 'cp':
            if len(parts) < 3:
                return "cp: missing file operand\r\n"
            
            source = parts[1]
            dest = parts[2]
            
            exists_src, src_path = self._path_exists(source)
            if not exists_src:
                return f"cp: cannot stat '{source}': No such file or directory\r\n"
            
            # Adiciona dest
            exists_dest, dest_path = self._path_exists(dest)
            parent_dest = dest_path.rsplit('/', 1)[0] or '/'
            name_dest = dest_path.rsplit('/', 1)[1]
            
            if parent_dest in self.filesystem:
                if name_dest not in self.filesystem[parent_dest]:
                    self.filesystem[parent_dest].append(name_dest)
            
            return ""
        
        # find
        elif command == 'find':
            return "find: command not fully implemented\r\n"
        
        # grep
        elif command == 'grep':
            if len(parts) < 2:
                return ""
            return "grep: command not fully implemented\r\n"
        
        # Comandos de rede adicionais
        elif command == 'ping':
            if len(parts) < 2:
                return "ping: missing host operand\r\n"
            host = parts[1]
            return f"""PING {host} (93.184.216.34) 56(84) bytes of data.
64 bytes from {host}: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from {host}: icmp_seq=2 ttl=64 time=0.098 ms
^C
--- {host} ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
\r\n"""
        
        elif command == 'netstat':
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.100:22        192.168.1.76:54321      ESTABLISHED
\r\n"""
        
        elif command == 'ss':
            return """Netid State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
tcp   LISTEN     0      128          *:22                *:*
tcp   LISTEN     0      128          *:80                *:*
tcp   ESTAB      0      0      192.168.1.100:22    192.168.1.76:54321
\r\n"""
        
        # Comandos de sistema
        elif command == 'df':
            return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       20511356 8234567  11235678  43% /
tmpfs            2048000   12345   2035655   1% /tmp
\r\n"""
        
        elif command == 'free':
            return """              total        used        free      shared  buff/cache   available
Mem:        4048000     1234567     1567890       12345     1245543     2567890
Swap:       2097152           0     2097152
\r\n"""
        
        elif command == 'top':
            return """top - {datetime.now().strftime('%H:%M:%S')} up 5 days, 3:42, 1 user, load average: 0.12, 0.34, 0.56
Tasks: 123 total,   1 running, 122 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.1 id,  0.3 wa,  0.0 hi,  0.1 si,  0.0 st
MiB Mem :   3953.1 total,   1531.2 free,   1205.5 used,   1216.4 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   2510.4 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  169692  13004  10020 S   0.0   0.3   0:01.23 systemd
\r\n"""
        
    def eof_received(self):
        return False
        
    def break_received(self, msec):
        pass
    
    def _draw_nano_interface(self, filename):
        """Desenha a interface do nano"""
        screen = "\033[2J\033[H"  # Limpa tela e move cursor para topo
        
        # Cabeçalho do GNU nano
        screen += f"  GNU nano 2.9.3                {filename}                           \r\n"
        screen += "\r\n"
        
        # Área de conteúdo com texto se houver
        if self.editor_content:
            for line in self.editor_content[:20]:
                screen += line + "\r\n"
            # Preenche linhas vazias restantes
            for _ in range(20 - len(self.editor_content)):
                screen += "\r\n"
        else:
            # Linhas vazias
            for _ in range(20):
                screen += "\r\n"
        
        # Rodapé com comandos
        screen += "^G Get Help  ^O Write Out ^W Where Is  ^K Cut Text  ^J Justify   ^C Cur Pos\r\n"
        screen += "^X Exit      ^R Read File ^\\ Replace   ^U Uncut Text^T To Spell  ^_ Go To Line"
        
        # NÃO adiciona nova linha no final - aguarda input do usuário
        return screen
    
    def _handle_editor_input(self, data):
        """Processa input quando está no editor nano"""
        # Ctrl+X - Sair
        if data == b'\x18':  # Ctrl+X
            self.in_editor = False
            
            # Salva arquivo se houver conteúdo
            parent_path = self.editor_file.rsplit('/', 1)[0] or '/'
            file_name = self.editor_file.rsplit('/', 1)[1]
            
            if parent_path in self.filesystem and file_name not in self.filesystem[parent_path]:
                self.filesystem[parent_path].append(file_name)
            
            # Limpa tela e volta ao prompt
            self._chan.write("\033[2J\033[H")  # Limpa tela
            self._send_prompt()
            return
        
        # Ctrl+C - Mostra posição do cursor
        elif data == b'\x03':
            # Mostra mensagem na área de status (ignora por agora)
            return
        
        # Enter - Nova linha
        elif data == b'\r' or data == b'\n':
            self.editor_content.append('')
            # Redesenha interface
            self._chan.write(self._draw_nano_interface(self.editor_file.split('/')[-1]))
            return
        
        # Backspace - Remove último caractere
        elif data == b'\x7f' or data == b'\x08':
            if self.editor_content and len(self.editor_content[-1]) > 0:
                self.editor_content[-1] = self.editor_content[-1][:-1]
            # Redesenha interface
            self._chan.write(self._draw_nano_interface(self.editor_file.split('/')[-1]))
            return
        
        # Outras teclas - adiciona ao conteúdo
        else:
            try:
                text = data.decode('utf-8', errors='ignore')
                if text.isprintable() or text == ' ':
                    # Se não há linhas, cria primeira
                    if not self.editor_content:
                        self.editor_content.append('')
                    # Adiciona caractere à última linha
                    self.editor_content[-1] += text
                    # Atualiza display
                    self._chan.write(text)
            except:
                pass
            
    def eof_received(self):
        return False
        
    def break_received(self, msec):
        pass
