import asyncio
import random
import os
import socket
import string
from typing import Dict, Any, List, Tuple
from pathlib import Path
import logging
from datetime import datetime, timedelta
import hashlib

from core.service_emulator.base_service import BaseService

class FTPService(BaseService):
    
    def __init__(self, port: int, config: Dict[str, Any]):
        super().__init__(port, config)
        self.name = "FTP Server"
        self.banner = config.get('banner', '220 ProFTPD 1.3.5 Server (Debian)')
        self.anonymous_login = config.get('anonymous_login', True)

        self.users = config.get('users', {})
        self.config_username = config.get('username', 'admin')
        self.config_password = config.get('password', 'admin123')
        
        if self.config_username and self.config_username not in self.users:
            self.users[self.config_username] = self.config_password

        if 'ftpuser' not in self.users:
            self.users['ftpuser'] = 'ftpuser123'
        
        self.virtual_root = Path("ftp_storage")
        self.current_user_dir: Dict[str, Path] = {}
        self.passive_ports = config.get('passive_ports', {'min': 49152, 'max': 65535})
        self.max_file_size = config.get('max_file_size', 100 * 1024 * 1024)  # 100MB
        self.allow_upload = config.get('allow_upload', True)
        self.allow_download = config.get('allow_download', True)
        self.idle_timeout = config.get('idle_timeout', 300)
        
        self.hostname = config.get('hostname', 'ubuntu-server')
        self.os_template = config.get('os_template', 'Ubuntu')
        self.any_auth = config.get('any_auth', True)
        self.brute_force_attempts = config.get('brute_force_attempts', 1)
        self.failed_attempts = {}
        
        self.virtual_root.mkdir(exist_ok=True, parents=True)
        self.create_realistic_filesystem()
        self.debug_directory_structure()
        
        self.data_connections: Dict[str, Any] = {}
        self.active_transfers: Dict[str, Dict] = {}
        
        self.logger.info(f"FTP Service initialized on port {port}")
        self.logger.info(f"Virtual root: {self.virtual_root.absolute()}")
        self.logger.info(f"Anonymous login: {self.anonymous_login}")
        self.logger.info(f"Allow upload: {self.allow_upload}")
        self.logger.info(f"Allow download: {self.allow_download}")
        self.logger.info(f"Configured users: {list(self.users.keys())}")
    
    def ensure_user_directory(self, username: str) -> Path:
        
        home_dir = self.virtual_root / "home"
        home_dir.mkdir(exist_ok=True, parents=True)
        
        user_dir = home_dir / username
        user_dir.mkdir(exist_ok=True, parents=True)
        
        if username.lower() == 'ftpuser':
            files_dir = user_dir / "files"
            files_dir.mkdir(exist_ok=True, parents=True)
            
            readme_file = files_dir / "readme.txt"
            if not readme_file.exists():
                readme_content = f"FTP User Files\n\nServer: {self.hostname}\nCreated: {datetime.now().strftime('%Y-%m-%d')}\n"
                readme_file.write_text(readme_content, encoding='utf-8')
            
            self.current_user_dir[username] = user_dir
            self.logger.info(f"[FTP] Created ftpuser directory with /files: {user_dir}")
            return user_dir
        
        common_subdirs = [
            'Desktop',
            'Documents',
            'Downloads',
            'Pictures',
            'Music',
            'Videos'
        ]
        
        for subdir in common_subdirs:
            subdir_path = user_dir / subdir
            subdir_path.mkdir(exist_ok=True)
            
            if subdir == 'Documents':
                notes_file = user_dir / subdir / "notes.txt"
                if not notes_file.exists():
                    notes_content = f"Personal notes for {username}\n\nSystem: {self.hostname}\nCreated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    notes_file.write_text(notes_content, encoding='utf-8')
                    
            elif subdir == 'Downloads':
                readme_file = user_dir / subdir / "README.txt"
                if not readme_file.exists():
                    readme_content = f"Download directory for {username}\n\nServer: {self.hostname}\n"
                    readme_file.write_text(readme_content, encoding='utf-8')
        
        self.current_user_dir[username] = user_dir
        self.logger.info(f"[FTP] Created user directory for {username}: {user_dir}")
        return user_dir

    def create_realistic_filesystem(self):
        home_dir = self.virtual_root / "home"
        home_dir.mkdir(exist_ok=True, parents=True)
        
        ftpuser_dir = home_dir / "ftpuser"
        ftpuser_dir.mkdir(exist_ok=True, parents=True)
        files_dir = ftpuser_dir / "files"
        files_dir.mkdir(exist_ok=True, parents=True)
        
        sample_file = files_dir / "readme.txt"
        if not sample_file.exists():
            sample_content = f"FTP User Files Directory\n\nServer: {self.hostname}\nUser: ftpuser\nCreated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            sample_file.write_text(sample_content, encoding='utf-8')
        
        if self.config_username and self.config_username.lower() != 'ftpuser':
            self.ensure_user_directory(self.config_username)
        
        self.logger.info(f"[FTP] Created simple filesystem: /home/ftpuser/files and /home/{self.config_username}/{{Documents,Downloads,...}}")
    
    def generate_system_log(self) -> str:
        log_entries = []
        for i in range(50):
            timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 10080))).strftime("%b %d %H:%M:%S")
            hostname = self.hostname
            
            processes = [
                ("systemd", "Started User Manager for UID 1000"),
                ("kernel", f"TCP: time wait bucket table overflow"),
                ("sshd", f"Accepted password for {self.config_username} from 192.168.1.{random.randint(1, 254)} port {random.randint(1000, 9999)}"),
                ("cron", f"(root) CMD (cd / && run-parts --report /etc/cron.hourly)"),
                ("ftpd", f"FTP session opened for {random.choice(list(self.users.keys()))}"),
                ("apache2", f"AH00094: Command line: '/usr/sbin/apache2'"),
                ("systemd-logind", f"New session {random.randint(1000, 9999)} of user {self.config_username}."),
                ("dbus-daemon", f"[session uid={random.randint(1000, 2000)} pid={random.randint(1000, 9999)}] Successfully activated service 'org.freedesktop.ColorManager'"),
                ("NetworkManager", f"<info>  [1700000000.0000] device (eth0): state change: ip-config -> ip-check (reason 'none')"),
                ("systemd-timesyncd", f"Synchronized to time server {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}:123 (ntp.ubuntu.com).")
            ]
            
            process, message = random.choice(processes)
            pid = random.randint(100, 9999)
            
            log_entries.append(f"{timestamp} {hostname} {process}[{pid}]: {message}")
        
        return "\n".join(sorted(log_entries))
    
    def generate_auth_log(self) -> str:
        log_entries = []
        for i in range(30):
            timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 720))).strftime("%b %d %H:%M:%S")
            hostname = self.hostname
            
            auth_events = [
                f"Accepted password for {self.config_username} from 192.168.1.{random.randint(1, 254)} port {random.randint(1000, 9999)} ssh2",
                f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}",
                f"Failed password for invalid user admin from {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)} port {random.randint(1000, 9999)} ssh2",
                f"Connection closed by authenticating user {self.config_username} {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)} port {random.randint(1000, 9999)} [preauth]",
                f"User {random.choice(list(self.users.keys()))} from {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)} logged into FTP server",
                f"PAM service(sshd) ignoring max retries; 6 > 3"
            ]
            
            process = "sshd"
            pid = random.randint(1000, 9999)
            message = random.choice(auth_events)
            
            log_entries.append(f"{timestamp} {hostname} {process}[{pid}]: {message}")
        
        return "\n".join(sorted(log_entries))
    
    async def handle_connection(self, reader, writer):
        client_ip = writer.get_extra_info('peername')[0]
        session_id = f"{client_ip}_{datetime.now().timestamp()}"
        
        self.log_connection(client_ip)
        
        writer.write(f"{self.banner}\r\n".encode())
        await writer.drain()
        
        session = {
            'authenticated': False,
            'username': None,
            'current_dir': Path('/'),
            'transfer_type': 'A',  # ASCII common
            'passive_mode': False,
            'data_reader': None,
            'data_writer': None,
            'data_port': None,
            'last_command': datetime.now()
        }
        
        try:
            while self.is_running:
                if (datetime.now() - session['last_command']).seconds > self.idle_timeout:
                    writer.write(b"421 Timeout.\r\n")
                    await writer.drain()
                    break
                
                data = await asyncio.wait_for(reader.readline(), timeout=1.0)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    continue
                
                session['last_command'] = datetime.now()
                
                self.log_command(client_ip, command)

                response = await self.process_command(command, session, client_ip, writer)

                writer.write(f"{response}\r\n".encode())
                await writer.drain()

                await self.simulate_human_delay()
                
                if command.upper().startswith("QUIT"):
                    break
                    
        except asyncio.TimeoutError:
            self.logger.debug(f"Connection timeout from {client_ip}")
        except Exception as e:
            self.logger.error(f"FTP error from {client_ip}: {e}")
        finally:
            
            if session.get('data_writer'):
                session['data_writer'].close()
                await session['data_writer'].wait_closed()
            
            writer.close()
            await writer.wait_closed()
            self.logger.info(f"FTP connection closed from {client_ip}")
    
    async def process_command(self, command: str, session: dict, client_ip: str, control_writer) -> str:
        cmd_parts = command.split()
        if not cmd_parts:
            return "500 Syntax error"
        
        cmd = cmd_parts[0].upper()
        
        if cmd == "USER":
            return self.handle_user(cmd_parts, session)
        
        elif cmd == "PASS":
            return self.handle_pass(cmd_parts, session, client_ip)
        
        elif cmd == "QUIT":
            return "221 Goodbye."
        
        elif cmd == "NOOP":
            return "200 NOOP ok."
        
        elif cmd == "SYST":
            return "215 UNIX Type: L8"
        
        elif cmd == "FEAT":
            features = [
                "211-Features:",
                " EPRT",
                " EPSV",
                " MDTM",
                " PASV",
                " REST STREAM",
                " SIZE",
                " TVFS",
                " UTF8",
                " MLST type*;size*;modify*;",
                " MLSD",
                " AUTH TLS",
                " PBSZ",
                " PROT",
                "211 End"
            ]
            return "\r\n".join(features)
                
        if not session['authenticated']:
            return "530 Please login with USER and PASS"

        if cmd == "PWD" or cmd == "XPWD":
            current = str(session["current_dir"]).replace('\\', '/')
            return f'257 "{current}" is the current directory'
        
        elif cmd == "CWD" or cmd == "XCWD":
            return self.handle_cwd(cmd_parts, session)
        
        elif cmd == "CDUP" or cmd == "XCUP":
            return self.handle_cdup(session)
        
        elif cmd == "TYPE":
            return self.handle_type(cmd_parts, session)
        
        elif cmd == "PASV":
            return await self.handle_pasv(session, client_ip)
        
        elif cmd == "PORT":
            return self.handle_port(cmd_parts, session)
        
        elif cmd == "LIST" or cmd == "NLST" or cmd == "MLSD":
            return await self.handle_list(cmd_parts, session, client_ip, control_writer)
        
        elif cmd == "RETR":
            return await self.handle_retr(cmd_parts, session, client_ip, control_writer)
        
        elif cmd == "STOR" or cmd == "APPE":
            return await self.handle_stor(cmd_parts, session, client_ip, control_writer, cmd)
        
        elif cmd == "DELE":
            return self.handle_dele(cmd_parts, session, client_ip)
        
        elif cmd == "MKD" or cmd == "XMKD":
            return self.handle_mkd(cmd_parts, session, client_ip)
        
        elif cmd == "RMD" or cmd == "XRMD":
            return self.handle_rmd(cmd_parts, session, client_ip)
        
        elif cmd == "RNFR":
            return self.handle_rnfr(cmd_parts, session)
        
        elif cmd == "RNTO":
            return self.handle_rnto(cmd_parts, session, client_ip)
        
        elif cmd == "SIZE":
            return self.handle_size(cmd_parts, session)
        
        elif cmd == "MDTM":
            return self.handle_mdtm(cmd_parts, session)
        
        elif cmd == "REST":
            return self.handle_rest(cmd_parts, session)
        
        else:
            return f"500 '{cmd}': command not understood"
    
    def handle_user(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Syntax error in parameters or arguments"
        
        username = cmd_parts[1]
        session['username'] = username
        
        if username.lower() == 'anonymous' and self.anonymous_login:
            session['authenticated'] = True
            return "230 Anonymous access granted, restrictions apply."
        
        return f"331 Password required for {username}"
    
    def handle_pass(self, cmd_parts: List[str], session: dict, client_ip: str) -> str:
        username = session.get('username')
        
        if not username:
            return "503 Login with USER first"
        
        if client_ip not in self.failed_attempts:
            self.failed_attempts[client_ip] = {
                'count': 0,
                'attempts': [],
                'last_attempt': datetime.now()
            }
        
        ip_data = self.failed_attempts[client_ip]
        
        # Debug logging
        self.logger.info(f"[DEBUG] FTP Brute-force check for {client_ip}: count={ip_data.get('count', 'N/A')}, brute_force_attempts={self.brute_force_attempts}, attempts_list_size={len(ip_data.get('attempts', []))}")
        
        time_since_last = (datetime.now() - ip_data.get('last_attempt', datetime.now())).total_seconds()
        if time_since_last > 300:  # 5 min
            self.logger.info(f"FTP Auto-expired failed_attempts for {client_ip} (inactive for {int(time_since_last)}s)")
            ip_data['count'] = 0
            ip_data['attempts'] = []
        
        ip_data['last_attempt'] = datetime.now()
        password = cmd_parts[1] if len(cmd_parts) > 1 else ""
        current_attempt = (username, password)
        
        if self.any_auth:
            if ip_data['count'] < self.brute_force_attempts - 1:
                ip_data['count'] += 1
                ip_data['attempts'].append(current_attempt)
                
                self.logger.info(f"FTP Brute-force test: failing attempt {ip_data['count']}/{self.brute_force_attempts} for {client_ip}")
                return "530 Login incorrect."
            
            if current_attempt in ip_data['attempts']:
                self.logger.info(f"FTP Brute-force test: rejecting identical credentials ({username}/{password}) for {client_ip}")
                return "530 Login incorrect."
            
            self.logger.info(f"FTP Brute-force test: success on attempt {ip_data['count']} for {client_ip}")
            session['authenticated'] = True
            
            ip_data['count'] = 0
            ip_data['attempts'] = []
            
            if username.lower() == 'anonymous':
                session['current_dir'] = Path('/pub')
                self.ensure_user_directory('anonymous')
            else:
                self.ensure_user_directory(username)
                session['current_dir'] = Path(f'/home/{username}')
            
            if username not in self.users:
                self.users[username] = 'any'
            
            return "230 Login successful."
        else:
            if username in self.users and self.users[username] == password:
                session['authenticated'] = True
                self.ensure_user_directory(username)
                session['current_dir'] = Path(f'/home/{username}')
                return "230 Login successful."
            else:
                return "530 Login incorrect."
    
    def handle_cwd(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing directory argument"
        
        target_dir = cmd_parts[1]
        
        self.logger.info(f"CWD command: '{target_dir}' from {session.get('username', 'unknown')}")

        target_dir = target_dir.replace('\\', '/')
        
        if target_dir.startswith('/'):
            new_path = Path(target_dir)
        else:
            current_str = str(session['current_dir']).replace('\\', '/')
            new_path = Path(current_str) / target_dir
        
        try:
            path_str = str(new_path).replace('\\', '/')
            
            import re
            path_str = re.sub(r'/+', '/', path_str)
            
            parts = []
            for part in path_str.split('/'):
                if not part or part == '.':
                    continue
                elif part == '..':
                    if parts:
                        parts.pop()
                else:
                    parts.append(part)
            
            normalized_path = '/' + '/'.join(parts) if parts else '/'
            
            self.logger.info(f"CWD: Normalized path: {normalized_path}")
            
            new_path = Path(normalized_path)
            
            path_str = normalized_path
            
            if path_str.startswith('/home/'):
                path_parts = path_str.split('/')
                if len(path_parts) >= 3:
                    username = path_parts[2]
                    
                    valid_users = list(self.users.keys())
                    if self.any_auth:
                        valid_users.append(username)
                    
                    if username in valid_users or self.any_auth:
                        self.logger.info(f"CWD: User directory for: {username}")
                        
                        virtual_path = self.ensure_user_directory(username)
                        
                        if len(path_parts) > 3:
                            subdirs = '/'.join(path_parts[3:])
                            virtual_path = virtual_path / subdirs
                            virtual_path.mkdir(exist_ok=True, parents=True)
                        
                        session['current_dir'] = new_path
                        return '250 Directory successfully changed.'
            
            relative_path = path_str.lstrip('/')
            virtual_path = self.virtual_root / relative_path.replace('/', os.sep)
            
            allowed_prefixes = ['pub/', 'tmp/', 'var/', 'etc/', 'usr/', 'opt/']
            if any(relative_path.startswith(prefix) for prefix in allowed_prefixes):
                virtual_path.mkdir(exist_ok=True, parents=True)
            
            if virtual_path.exists() and virtual_path.is_dir():
                session['current_dir'] = new_path
                return '250 Directory successfully changed.'
            else:
                self.logger.warning(f"CWD: Directory not found: {new_path}")
                return '550 Failed to change directory. Directory does not exist.'
                
        except Exception as e:
            self.logger.error(f"CWD error: {e}")
            import traceback
            traceback.print_exc()
            return '550 Failed to change directory.'
    
    def handle_cdup(self, session: dict) -> str:
        if str(session['current_dir']) == '/':
            return '250 Directory already at root.'
        
        session['current_dir'] = session['current_dir'].parent
        return '250 Directory successfully changed.'
    
    def handle_type(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing type argument"
        
        type_code = cmd_parts[1].upper()
        if type_code in ['A', 'I']:
            session['transfer_type'] = type_code
            return f"200 Type set to {type_code}"
        else:
            return "504 Type not implemented"
    
    async def handle_pasv(self, session: dict, client_ip: str) -> str:
        try:
            port = random.randint(self.passive_ports['min'], self.passive_ports['max'])
            
            self.logger.debug(f"PASV: Attempting to bind to port {port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(1)
            sock.setblocking(False)
            
            self.logger.info(f"PASV: Successfully bound to port {port}")
            
            session['pasv_socket'] = sock
            session['pasv_port'] = port
            session['passive_mode'] = True
            session['active_mode'] = None
            
            local_ip = '0.0.0.0'
            
            try:
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_sock.connect(('8.8.8.8', 80))
                local_ip = temp_sock.getsockname()[0]
                temp_sock.close()
            except:
                try:
                    local_ip = socket.gethostbyname(socket.gethostname())
                except:
                    local_ip = '192.168.1.100'
            
            if local_ip.startswith('127.'):
                try:
                    import netifaces
                    for interface in netifaces.interfaces():
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr_info in addrs[netifaces.AF_INET]:
                                ip = addr_info['addr']
                                if not ip.startswith('127.'):
                                    local_ip = ip
                                    break
                except ImportError:
                    local_ip = '192.168.1.100'
            
            self.logger.info(f"PASV: Using IP {local_ip} for passive mode")
            
            # IP format for FTP format (x,x,x,x)
            ip_parts = local_ip.split('.')
            if len(ip_parts) != 4:
                ip_parts = ['192', '168', '1', '100']  # Fallback
            
            ip_address = ','.join(ip_parts)
            
            p1 = port // 256
            p2 = port % 256
            
            return f"227 Entering Passive Mode ({ip_address},{p1},{p2})"
            
        except Exception as e:
            self.logger.error(f"Failed to create passive socket: {e}")
            import traceback
            traceback.print_exc()
            return "425 Can't open data connection."
        
    async def accept_pasv_connection(self, session: dict):
        try:
            sock = session.get('pasv_socket')
            if not sock:
                self.logger.error("No passive socket in session")
                return None
            
            self.logger.info(f"Waiting for passive connection on port {session.get('pasv_port')}...")
            
            loop = asyncio.get_event_loop()
            client_sock, addr = await asyncio.wait_for(
                loop.sock_accept(sock),
                timeout=10.0
            )
            
            self.logger.info(f"Passive connection accepted from {addr}")
            
            reader, writer = await asyncio.open_connection(sock=client_sock)
            
            return reader, writer
            
        except asyncio.TimeoutError:
            self.logger.warning("Passive connection timeout - client did not connect")
            return None
        except Exception as e:
            self.logger.error(f"Error accepting passive connection: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            if 'pasv_socket' in session:
                try:
                    session['pasv_socket'].close()
                except:
                    pass
                session.pop('pasv_socket', None)
    
    def handle_port(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Syntax error in parameters"
        
        try:
            parts = cmd_parts[1].split(',')
            if len(parts) != 6:
                return "501 Invalid PORT format"
            
            ip = '.'.join(parts[:4])
            port = (int(parts[4]) * 256) + int(parts[5])
            
            session['active_mode'] = {'ip': ip, 'port': port}
            session['passive_mode'] = False
            
            return "200 PORT command successful"
            
        except Exception as e:
            self.logger.error(f"Invalid PORT command: {e}")
            return "501 Syntax error in parameters"
    
    async def handle_list(self, cmd_parts: List[str], session: dict, client_ip: str, control_writer) -> str:
        target_dir = session['current_dir']
        if len(cmd_parts) > 1:
            dir_arg = cmd_parts[1]
            if dir_arg.startswith('/'):
                target_dir = Path(dir_arg)
            else:
                target_dir = target_dir / dir_arg
        
        target_str = str(target_dir).replace('\\', '/').lstrip('/')
        virtual_path = self.virtual_root / target_str.replace('/', os.sep)
        
        self.logger.info(f"LIST: target_dir={target_dir}, virtual_path={virtual_path}, exists={virtual_path.exists()}")
        
        if not virtual_path.exists() or not virtual_path.is_dir():
            self.logger.warning(f"LIST: Directory not found: {virtual_path}")
            return "550 Directory not found"
        
        data_writer = await self.get_data_connection(session, client_ip)
        if not data_writer:
            return "425 Can't open data connection"
        
        listing = self.generate_directory_listing(virtual_path)
        
        control_writer.write(b"150 Opening ASCII mode data connection for file list\r\n")
        await control_writer.drain()
        
        data_writer.write(listing.encode('utf-8'))
        await data_writer.drain()
        data_writer.close()
        await data_writer.wait_closed()

        if session.get('data_writer'):
            session['data_writer'] = None
        
        return "226 Transfer complete"
    
    async def handle_retr(self, cmd_parts: List[str], session: dict, client_ip: str, control_writer) -> str:
        if not self.allow_download:
            return "550 Permission denied"
        
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        filename = cmd_parts[1]
        
        if filename.startswith('/'):
            file_path = Path(filename)
        else:
            file_path = session['current_dir'] / filename
        
        virtual_path = self.virtual_root / str(file_path).lstrip('/')
        
        if not virtual_path.exists() or not virtual_path.is_file():
            return "550 File not found"
        
        file_size = virtual_path.stat().st_size
        if file_size > self.max_file_size:
            return "552 Requested file action aborted. Exceeded storage allocation"
        
        data_writer = await self.get_data_connection(session, client_ip)
        if not data_writer:
            return "425 Can't open data connection"
        
        control_writer.write(f"150 Opening {session['transfer_type']} mode data connection for {filename} ({file_size} bytes)\r\n".encode())
        await control_writer.drain()
        
        try:
            with open(virtual_path, 'rb') as f:
                chunk_size = 8192
                total_sent = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    data_writer.write(chunk)
                    await data_writer.drain()
                    total_sent += len(chunk)
                    
                    await asyncio.sleep(0.001)  # 1ms delay por chunk
                
                self.logger.info(f"File downloaded: {filename} ({total_sent} bytes) by {client_ip}")
                
        except Exception as e:
            self.logger.error(f"Error sending file {filename}: {e}")
            return "451 Requested action aborted. Local error in processing"
        
        finally:
            data_writer.close()
            await data_writer.wait_closed()
            if session.get('data_writer'):
                session['data_writer'] = None
        
        return "226 Transfer complete"
    
    async def handle_stor(self, cmd_parts: List[str], session: dict, client_ip: str, control_writer, cmd: str) -> str:
        if not self.allow_upload:
            self.logger.warning(f"Upload blocked from {client_ip} - upload disabled in config")
            return "553 Requested action not taken. Permission denied"
        
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        filename = cmd_parts[1]
        
        upload_dir = None
        
        try:
            current_dir = session.get('current_dir', Path('/'))
            current_str = str(current_dir).replace('\\', '/')
            
            self.logger.info(f"STOR: Current directory string: {current_str}")
            
            if current_str == '/':
                username = session.get('username', 'anonymous')
                if username and username.lower() != 'anonymous':
                    upload_dir = self.virtual_root / "home" / username
                else:
                    upload_dir = self.virtual_root / "pub" / "incoming"
            elif current_str.startswith('/home/'):
                parts = current_str.split('/')
                if len(parts) >= 3:
                    username = parts[2]
                    upload_dir = self.virtual_root / "home" / username
                    
                    if len(parts) > 3:
                        subdirs = '/'.join(parts[3:])
                        upload_dir = upload_dir / subdirs
            elif current_str.startswith('/pub/'):
                relative_path = current_str.lstrip('/')
                upload_dir = self.virtual_root / relative_path.replace('/', os.sep)
            else:
                relative_path = current_str.lstrip('/')
                upload_dir = self.virtual_root / relative_path.replace('/', os.sep)
            
            if upload_dir is None:
                username = session.get('username', 'anonymous')
                if username.lower() == 'anonymous':
                    upload_dir = self.virtual_root / "pub" / "incoming"
                else:
                    upload_dir = self.virtual_root / "home" / username
            
            upload_dir.mkdir(exist_ok=True, parents=True)
            
            self.logger.info(f"STOR: Upload directory: {upload_dir}")
            
            safe_name = self.sanitize_filename(filename)
            file_path = upload_dir / safe_name
            
            self.logger.info(f"STOR: Full file path: {file_path}")
            
            is_append = (cmd == "APPE")
            
            data_reader = await self.get_data_connection_reader(session, client_ip)
            if not data_reader:
                return "425 Can't open data connection"
            
            control_writer.write(f"150 Opening {session['transfer_type']} mode data connection for {filename}\r\n".encode())
            await control_writer.drain()
            
            mode = 'ab' if is_append else 'wb'
            total_received = 0
            
            with open(file_path, mode) as f:
                chunk_size = 8192
                
                while True:
                    chunk = await data_reader.read(chunk_size)
                    if not chunk:
                        break
                    
                    f.write(chunk)
                    total_received += len(chunk)
                    
                    if total_received > self.max_file_size:
                        return "552 Requested file action aborted. Exceeded storage allocation"
                
                self.save_upload_metadata(file_path, client_ip, session['username'], total_received)
                
                self.logger.info(f"STOR: File uploaded: {filename} ({total_received} bytes)")
                self.logger.warning(f"STOR: CAPTURED FILE from {client_ip}: {file_path}")
                
            return "226 Transfer complete"
                
        except Exception as e:
            self.logger.error(f"STOR: Error receiving file: {e}")
            import traceback
            traceback.print_exc()
            return "451 Requested action aborted. Local error in processing"
        
        finally:
            if session.get('data_reader'):
                session['data_reader'] = None
    
    def debug_directory_structure(self):
        import os
        self.logger.info("=== FTP DIRECTORY STRUCTURE ===")
        
        def list_dir(path, indent=0):
            try:
                for item in sorted(os.listdir(path)):
                    full_path = os.path.join(path, item)
                    if os.path.isdir(full_path):
                        self.logger.info("  " * indent + f"[DIR] {item}/")
                        list_dir(full_path, indent + 1)
                    else:
                        size = os.path.getsize(full_path)
                        self.logger.info("  " * indent + f"[FILE] {item} ({size} bytes)")
            except Exception as e:
                self.logger.error(f"Error listing {path}: {e}")
        
        list_dir(str(self.virtual_root))
        self.logger.info("=== END STRUCTURE ===")

    def save_upload_metadata(self, file_path: Path, client_ip: str, username: str, size: int):
        import json
        
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": client_ip,
            "username": username or "anonymous",
            "original_filename": file_path.name,
            "size": size,
            "sha256": self.calculate_file_hash(file_path),
            "saved_path": str(file_path.absolute()),
            "honeypot_service": "ftp"
        }
        
        meta_path = file_path.with_suffix('.meta.json')
        meta_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    
    def calculate_file_hash(self, file_path: Path) -> str:
        try:
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "unknown"
    
    def sanitize_filename(self, filename: str) -> str:
        safe_chars = "-_.() " + string.ascii_letters + string.digits
        filename = ''.join(c for c in filename if c in safe_chars)
        
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250 - len(ext)] + ext
        
        if not filename:
            filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        
        return filename
    
    async def handle_data_connection(self, reader, writer):
        try:
            addr = writer.get_extra_info('peername')
            self.logger.debug(f"Data connection from {addr}")
            await asyncio.sleep(0.1)
        except Exception as e:
            self.logger.error(f"Error in data connection handler: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def get_data_connection(self, session: dict, client_ip: str):
        try:
            if session.get('passive_mode'):
                result = await self.accept_pasv_connection(session)
                if result:
                    reader, writer = result
                    session['data_writer'] = writer
                    session['data_reader'] = reader
                    return writer
            
            elif session.get('active_mode'):
                active = session['active_mode']
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(active['ip'], active['port']),
                        timeout=10.0
                    )
                    session['data_writer'] = writer
                    session['data_reader'] = reader
                    return writer
                except (asyncio.TimeoutError, ConnectionError) as e:
                    self.logger.error(f"Active connection failed: {e}")
                    return None
            
            return None
        except Exception as e:
            self.logger.error(f"Data connection failed: {e}")
            return None
    
    async def get_data_connection_reader(self, session: dict, client_ip: str):
        try:
            if session.get('passive_mode'):
                result = await self.accept_pasv_connection(session)
                if result:
                    reader, writer = result
                    session['data_reader'] = reader
                    session['data_writer'] = writer
                    return reader
            else:
                active = session.get('active_mode')
                if active:
                    reader, writer = await asyncio.open_connection(
                        active['ip'],
                        active['port']
                    )
                    session['data_reader'] = reader
                    session['data_writer'] = writer
                    return reader
            
            return None
        except Exception as e:
            self.logger.error(f"Data connection failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    async def accept_connection(self, server):
        async def _accept():
            async with server:
                return await server.serve_connection()
        
        task = asyncio.create_task(_accept())
        try:
            return await asyncio.wait_for(task, timeout=10.0)
        finally:
            task.cancel()
    
    def generate_directory_listing(self, virtual_path: Path) -> str:
        entries = []
        
        entries.append("drwxr-xr-x   2 root     root         4096 Jan 15 09:30 .")
        entries.append("drwxr-xr-x  18 root     root         4096 Jan 15 09:30 ..")
        
        for item in sorted(virtual_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                if item.is_dir():
                    perm = "drwxr-xr-x"
                    size = 4096
                else:
                    perm = "-rw-r--r--"
                    size = item.stat().st_size
                
                import time
                timestamp = time.time() - random.randint(0, 180*24*3600)  # Last 180 days
                time_str = time.strftime("%b %d %H:%M", time.localtime(timestamp))
                
                if "home" in str(item):
                    if item.is_dir():
                        owner = item.name
                        group = "users"
                    else:
                        if item.name in self.users:
                            owner = item.name
                        else:
                            owner = "ftp"
                        group = "users"
                elif "etc" in str(item) or "var" in str(item) or "root" in str(item):
                    owner = "root"
                    group = "root"
                elif "pub" in str(item):
                    owner = "ftp"
                    group = "ftp"
                else:
                    owner = "ftp"
                    group = "ftp"
                
                entries.append(f"{perm}   1 {owner:<8} {group:<8} {size:>12} {time_str} {item.name}")
            except Exception as e:
                self.logger.error(f"Error listing item {item}: {e}")
                continue
        
        return "\r\n".join(entries) + "\r\n"
    
    def handle_dele(self, cmd_parts: List[str], session: dict, client_ip: str) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        filename = cmd_parts[1]
        
        if "pub/incoming" in str(session['current_dir']):
            file_path = self.virtual_root / "pub" / "incoming" / filename
            if file_path.exists() and file_path.is_file():
                try:
                    file_path.unlink()
                    meta_path = file_path.with_suffix('.meta.json')
                    if meta_path.exists():
                        meta_path.unlink()
                    return "250 DELE command successful"
                except:
                    return "550 Delete operation failed"
        
        return "550 Permission denied"
    
    def handle_mkd(self, cmd_parts: List[str], session: dict, client_ip: str) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing directory name"
        
        dirname = cmd_parts[1]
        
        if dirname.startswith('/'):
            dir_path = Path(dirname)
        else:
            dir_path = session['current_dir'] / dirname
        
        virtual_path = self.virtual_root / str(dir_path).lstrip('/')
        
        allowed_prefixes = [
            'pub/incoming',
            'Users',
            'tmp',
            'backup',
            'data'
        ]
        
        dir_str = str(dir_path).lstrip('/')
        is_allowed = any(dir_str.startswith(prefix) for prefix in allowed_prefixes)
        
        if is_allowed:
            try:
                virtual_path.mkdir(exist_ok=True, parents=True)
                return f'257 "{dirname}" directory created'
            except Exception as e:
                self.logger.error(f"Create directory failed: {e}")
                return "550 Create directory operation failed"
        else:
            return "553 Requested action not taken. Permission denied"
    
    def handle_rmd(self, cmd_parts: List[str], session: dict, client_ip: str) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing directory name"
        
        dirname = cmd_parts[1]
        
        if "pub/incoming" in str(session['current_dir']):
            dir_path = self.virtual_root / "pub" / "incoming" / dirname
            if dir_path.exists() and dir_path.is_dir():
                try:
                    if any(dir_path.iterdir()):
                        return "550 Directory not empty"
                    dir_path.rmdir()
                    return "250 RMD command successful"
                except:
                    return "550 Remove directory operation failed"
        
        return "550 Permission denied"
    
    def handle_rnfr(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        old_name = cmd_parts[1]
        session['rename_from'] = old_name
        return "350 Ready for destination name"
    
    def handle_rnto(self, cmd_parts: List[str], session: dict, client_ip: str) -> str:
        if 'rename_from' not in session:
            return "503 RNFR required first"
        
        if len(cmd_parts) < 2:
            return "501 Missing destination name"
        
        old_name = session['rename_from']
        new_name = cmd_parts[1]
        
        if "pub/incoming" in str(session['current_dir']):
            old_path = self.virtual_root / "pub" / "incoming" / old_name
            new_path = self.virtual_root / "pub" / "incoming" / new_name
            
            if old_path.exists():
                try:
                    old_path.rename(new_path)
                    
                    old_meta = old_path.with_suffix('.meta.json')
                    new_meta = new_path.with_suffix('.meta.json')
                    if old_meta.exists():
                        old_meta.rename(new_meta)
                    
                    del session['rename_from']
                    return "250 Rename successful"
                except:
                    return "550 Rename operation failed"
        
        return "550 Permission denied"
    
    def handle_size(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        filename = cmd_parts[1]
        
        if filename.startswith('/'):
            file_path = Path(filename)
        else:
            file_path = session['current_dir'] / filename
        
        virtual_path = self.virtual_root / str(file_path).lstrip('/')
        
        if virtual_path.exists() and virtual_path.is_file():
            size = virtual_path.stat().st_size
            return f"213 {size}"
        else:
            return "550 File not found"
    
    def handle_mdtm(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing filename"
        
        filename = cmd_parts[1]
        
        if filename.startswith('/'):
            file_path = Path(filename)
        else:
            file_path = session['current_dir'] / filename
        
        virtual_path = self.virtual_root / str(file_path).lstrip('/')
        
        if virtual_path.exists():
            import time
            mtime = virtual_path.stat().st_mtime
            # Formato: YYYYMMDDHHMMSS
            time_str = time.strftime("%Y%m%d%H%M%S", time.localtime(mtime))
            return f"213 {time_str}"
        else:
            return "550 File not found"
    
    def handle_rest(self, cmd_parts: List[str], session: dict) -> str:
        if len(cmd_parts) < 2:
            return "501 Missing restart offset"
        
        try:
            offset = int(cmd_parts[1])
            session['restart_offset'] = offset
            return f"350 Restarting at {offset}. Send STORE or RETRIEVE to initiate transfer"
        except:
            return "501 Invalid restart offset"
