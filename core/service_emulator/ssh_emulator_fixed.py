import asyncio
import asyncssh
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

class SSHService:
    """SSH Honeypot usando asyncssh - implementação REAL do protocolo SSH"""
    
    def __init__(self, port: int, config: dict):
        self.port = port
        self.config = config
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3')
        self.users = config.get('users', {
            'admin': 'admin123',
            'root': 'password',
            'user': '123456',
            'test': 'test'
        })
        self.is_running = False
        self.server = None
        self.server_task = None
        
        # Setup logging
        self.setup_logging()
        
        # Gera chave SSH para o servidor
        self.host_key = None
    
    def setup_logging(self):
        """Configura logging"""
        Path("logs").mkdir(exist_ok=True)
        self.log_file = "logs/ssh_honeypot.jsonl"
    
    async def generate_host_key(self):
        """Gera chave SSH para o servidor"""
        try:
            # Tenta carregar chave existente
            key_path = Path("logs/ssh_host_key")
            if key_path.exists():
                self.host_key = asyncssh.read_private_key(str(key_path))
            else:
                # Gera nova chave RSA
                self.host_key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
                # Salva para reutilizar
                key_path.write_bytes(self.host_key.export_private_key())
                print(f"[SSH] Generated new host key: {key_path}")
        except Exception as e:
            print(f"[SSH] Error generating key: {e}")
            # Gera chave em memória
            self.host_key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
    
    def log_event(self, event_type: str, details: dict):
        """Regista evento detalhado"""
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
            
            # Console output
            if event_type == "connection":
                print(f"[SSH] Connection from {details.get('client_ip')}")
            elif event_type == "login_attempt":
                status = "✓" if details.get('success') else "✗"
                print(f"[SSH] {status} Login: {details.get('username')} from {details.get('client_ip')}")
            elif event_type == "command":
                print(f"[SSH] Cmd: {details.get('username')}@{details.get('client_ip')}: {details.get('command')}")
        except:
            pass
    
    async def start(self):
        """Inicia o servidor SSH"""
        print(f"[SSH] Starting SSH honeypot on port {self.port}")
        print(f"[SSH] Logs: {self.log_file}")
        print(f"[SSH] Accepted users: {', '.join(self.users.keys())}")
        
        self.is_running = True
        
        try:
            # Gera chave do host
            await self.generate_host_key()
            
            # Inicia servidor asyncssh
            self.server = await asyncssh.create_server(
                lambda: SSHServer(self),
                '',  # bind em todas as interfaces
                self.port,
                server_host_keys=[self.host_key],
                server_version=self.banner.replace('SSH-2.0-', ''),
                reuse_address=True,
                login_timeout=60
            )
            
            print(f"[SSH] Listening on 0.0.0.0:{self.port}")
            print(f"[SSH] Test: ssh admin@localhost -p {self.port}")
            print(f"[SSH] Default passwords: admin123, password, test")
            
            # Mantém servidor rodando
            async with self.server:
                await self.server.wait_closed()
                
        except asyncssh.Error as e:
            print(f"[SSH] AsyncSSH error: {e}")
        except OSError as e:
            if e.errno == 10013:
                print(f"[SSH] ⚠ Port {self.port} requires admin privileges on Windows")
                print(f"[SSH] Run as Administrator or use port > 1024")
            else:
                print(f"[SSH] Cannot bind to port {self.port}: {e}")
        except Exception as e:
            print(f"[SSH] Error: {e}")
        finally:
            self.is_running = False
            
    async def stop(self):
        """Para o servidor"""
        print(f"[SSH] Stopping SSH honeypot...")
        self.is_running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print(f"[SSH] Stopped")


class SSHServerSession(asyncssh.SSHServerSession):
    """Sessão SSH interativa - shell honeypot"""
    
    def __init__(self, ssh_service, username, client_ip):
        self.ssh_service = ssh_service
        self.username = username
        self.client_ip = client_ip
        self.cwd = '/home/admin'
        
    def connection_made(self, chan):
        self._chan = chan
        
    def shell_requested(self):
        return True
        
    def session_started(self):
        # Envia welcome message
        welcome = "\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-20-generic x86_64)\r\n\r\n"
        welcome += " * Documentation:  https://help.ubuntu.com\r\n"
        welcome += " * Management:     https://landscape.canonical.com\r\n"
        welcome += " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        welcome += "Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y") + f" from {self.client_ip}\r\n"
        
        self._chan.write(welcome)
        self._send_prompt()
        
    def _send_prompt(self):
        prompt = f"{self.username}@honeypot-server:~$ "
        self._chan.write(prompt)
        
    def data_received(self, data, datatype):
        # Processa comando
        command = data.strip()
        
        if not command:
            self._send_prompt()
            return
            
        # Log comando
        self.ssh_service.log_event("command", {
            "client_ip": self.client_ip,
            "username": self.username,
            "command": command
        })
        
        # Processa
        response = self.process_command(command)
        self._chan.write(response)
        
        # Verifica exit
        if command.lower() in ['exit', 'logout', 'quit']:
            self._chan.exit(0)
        else:
            self._send_prompt()
            
    def process_command(self, command: str) -> str:
        """Processa comandos Linux - resposta realista"""
        cmd = command.strip()
        
        # Sistema
        if cmd == 'whoami':
            return f"{self.username}\r\n"
        elif cmd == 'pwd':
            return f"{self.cwd}\r\n"
        elif cmd == 'hostname':
            return "honeypot-server\r\n"
        elif cmd == 'id':
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\r\n"
            
        # Lista arquivos
        elif cmd.startswith('ls'):
            if '-la' in cmd or '-l' in cmd:
                return """total 32
drwxr-xr-x 4 admin admin 4096 Dec 24 10:30 .
drwxr-xr-x 3 root  root  4096 Dec 20 15:22 ..
-rw-r--r-- 1 admin admin  220 Dec 20 15:22 .bash_logout
-rw-r--r-- 1 admin admin 3771 Dec 20 15:22 .bashrc
drwx------ 2 admin admin 4096 Dec 24 09:15 .cache
drwxr-xr-x 2 admin admin 4096 Dec 24 10:30 Documents
drwxr-xr-x 2 admin admin 4096 Dec 24 10:30 Downloads
-rw-r--r-- 1 admin admin  807 Dec 20 15:22 .profile
\r\n"""
            else:
                return "Documents  Downloads  Pictures  Videos\r\n"
                
        # Informações do sistema  
        elif cmd.startswith('uname'):
            if '-a' in cmd:
                return "Linux honeypot-server 4.15.0-20-generic #21-Ubuntu SMP x86_64 GNU/Linux\r\n"
            else:
                return "Linux\r\n"
        elif cmd == 'cat /etc/os-release':
            return """NAME="Ubuntu"
VERSION="18.04.6 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.6 LTS"
VERSION_ID="18.04"
\r\n"""
        elif cmd == 'cat /etc/passwd':
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
mysql:x:111:118:MySQL Server:/nonexistent:/bin/false
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
\r\n"""
            
        # Processos
        elif cmd.startswith('ps'):
            return """  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 ps
\r\n"""
        elif cmd == 'top' or cmd == 'htop':
            return "top - command not available in this shell\r\nPress Ctrl+C to continue\r\n"
            
        # Rede
        elif cmd == 'ifconfig' or cmd == 'ip addr':
            return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
\r\n"""
        elif cmd == 'netstat -an' or cmd == 'ss -an':
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
\r\n"""
            
        # Outros comandos comuns
        elif cmd.startswith('cd '):
            new_dir = cmd[3:].strip()
            if new_dir == '..':
                self.cwd = '/home'
            elif new_dir.startswith('/'):
                self.cwd = new_dir
            else:
                self.cwd = f"{self.cwd}/{new_dir}"
            return ""
        elif cmd == 'clear':
            return "\033[2J\033[H"  # ANSI clear screen
        elif cmd.startswith('echo '):
            return cmd[5:] + "\r\n"
        elif cmd.startswith('cat '):
            filename = cmd[4:].strip()
            return f"cat: {filename}: No such file or directory\r\n"
            
        # Comando desconhecido
        else:
            return f"bash: {cmd.split()[0] if cmd else cmd}: command not found\r\n"
            
    def eof_received(self):
        return False
        
    def break_received(self, msec):
        pass


class SSHServer(asyncssh.SSHServer):
    """Servidor SSH - gerencia autenticação"""
    
    def __init__(self, ssh_service):
        self.ssh_service = ssh_service
        
    def connection_made(self, conn):
        self.conn = conn
        client_ip = conn.get_extra_info('peername')[0]
        
        self.ssh_service.log_event("connection", {
            "client_ip": client_ip,
            "client_version": conn.get_extra_info('client_version', 'unknown')
        })
        
    def connection_lost(self, exc):
        if hasattr(self, 'conn'):
            client_ip = self.conn.get_extra_info('peername')[0]
            self.ssh_service.log_event("disconnection", {"client_ip": client_ip})
        
    def begin_auth(self, username):
        # Aceita qualquer username para monitorar
        return True
        
    def password_auth_supported(self):
        return True
        
    def public_key_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        """Valida password - ACEITA SEMPRE para monitorar ataques"""
        client_ip = self.conn.get_extra_info('peername')[0]
        
        # Verifica se é uma senha conhecida
        is_valid = username in self.ssh_service.users and self.ssh_service.users[username] == password
        
        # Log da tentativa
        self.ssh_service.log_event("login_attempt", {
            "client_ip": client_ip,
            "username": username,
            "password": password,
            "success": True,  # Sempre aceita
            "valid_credentials": is_valid
        })
        
        # SEMPRE ACEITA para manter atacante conectado
        return True
        
    def validate_public_key(self, username, key):
        """Aceita qualquer chave pública"""
        client_ip = self.conn.get_extra_info('peername')[0]
        
        self.ssh_service.log_event("login_attempt", {
            "client_ip": client_ip,
            "username": username,
            "auth_method": "publickey",
            "key_type": key.get_algorithm(),
            "success": True
        })
        
        return True
        
    def session_requested(self):
        # Retorna nossa sessão customizada
        client_ip = self.conn.get_extra_info('peername')[0]
        username = self.conn.get_extra_info('username', 'unknown')
        
        return SSHServerSession(self.ssh_service, username, client_ip)
