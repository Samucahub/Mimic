"""
Emulador de servidor FTP
"""
import asyncio
import random
from typing import Dict, Any
from .base_service import BaseService

class FTPService(BaseService):
    """Emula um servidor FTP"""
    
    def __init__(self, port: int, config: Dict[str, Any]):
        super().__init__(port, config)
        self.name = "FTP Server"
        self.banner = config.get('banner', '220 ProFTPD 1.3.5 Server')
        self.anonymous_login = config.get('anonymous_login', True)
        self.users = config.get('users', {})
        self.current_dir = "/"
        self.fake_filesystem = self.create_fake_filesystem()
        
    def create_fake_filesystem(self) -> Dict:
        """Cria um sistema de ficheiros falso"""
        return {
            "/": {
                "type": "directory",
                "permissions": "drwxr-xr-x",
                "contents": ["pub", "etc", "bin", "usr"]
            },
            "/pub": {
                "type": "directory",
                "permissions": "drwxr-xr-x",
                "contents": ["readme.txt", "data.zip"]
            },
            "/pub/readme.txt": {
                "type": "file",
                "permissions": "-rw-r--r--",
                "size": 1024,
                "content": "Welcome to the FTP server\nThis is a honeypot system\n"
            },
            "/etc": {
                "type": "directory",
                "permissions": "drwxr-xr-x",
                "contents": ["passwd", "shadow", "hosts"]
            }
        }
    
    async def handle_connection(self, reader, writer):
        """Manipula conexão FTP"""
        client_ip = writer.get_extra_info('peername')[0]
        self.log_connection(client_ip)
        
        # Envia banner
        writer.write(f"{self.banner}\r\n".encode())
        await writer.drain()
        
        authenticated = False
        username = None
        
        try:
            while self.is_running:
                data = await reader.read(1024)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    continue
                
                # Ignora linhas vazias ou apenas \r\n
                if command in ['\r', '\n', '\r\n', '']:
                    continue
                    
                self.log_command(client_ip, command)
                
                # Parse comando - remove espaços extras
                cmd_parts = command.split()
                if not cmd_parts:
                    continue
                    
                cmd_upper = cmd_parts[0].upper()
                
                # USER command
                if cmd_upper == "USER":
                    if len(cmd_parts) > 1:
                        username = cmd_parts[1]
                        response = "331 Password required for " + username
                    else:
                        response = "501 Missing username"
                    
                # PASS command
                elif cmd_upper == "PASS":
                    if not username:
                        response = "503 Login with USER first"
                    else:
                        password = cmd_parts[1] if len(cmd_parts) > 1 else ""
                        # Aceita qualquer password (honeypot)
                        authenticated = True
                        response = "230 User logged in, proceed"
                
                # Outros comandos
                else:
                    response = await self.process_ftp_command(command, username, authenticated)
                
                # Envia resposta
                writer.write(f"{response}\r\n".encode())
                await writer.drain()
                
                # Quit command
                if cmd_upper == "QUIT":
                    break
                
                # Delay humano
                await self.simulate_human_delay()
                
        except Exception as e:
            self.logger.error(f"FTP error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass  # Ignora erros ao fechar conexão
    
    async def process_ftp_command(self, command: str, username: str, authenticated: bool) -> str:
        """Processa comandos FTP (exceto USER e PASS que são tratados separadamente)"""
        cmd_parts = command.split()
        if not cmd_parts:
            return "500 Unknown command"
            
        cmd = cmd_parts[0].upper()
        
        if cmd == "SYST":
            return "215 UNIX Type: L8"
        
        elif cmd == "FEAT":
            return "211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n211 End"
        
        elif cmd == "PWD" or cmd == "XPWD":
            return f'257 "{self.current_dir}" is the current directory'
        
        elif cmd == "TYPE":
            return "200 Type set to I"
        
        elif cmd == "CWD" or cmd == "XCWD":
            # Change working directory
            if not authenticated:
                return "530 Please login with USER and PASS"
            if len(cmd_parts) > 1:
                target_dir = cmd_parts[1]
                self.current_dir = target_dir if target_dir.startswith('/') else f"{self.current_dir}/{target_dir}"
                return f"250 CWD command successful"
            return "501 Invalid directory"
        
        elif cmd == "CDUP" or cmd == "XCUP":
            if not authenticated:
                return "530 Please login with USER and PASS"
            return "250 CDUP command successful"
        
        elif cmd == "PORT":
            # Modo ativo FTP - aceita mas não faz nada (honeypot)
            return "200 PORT command successful"
        
        elif cmd == "PASV":
            # Simula modo passivo
            port1 = random.randint(100, 200)
            port2 = random.randint(1, 255)
            return f"227 Entering Passive Mode (127,0,0,1,{port1},{port2})"
        
        elif cmd == "LIST" or cmd == "NLST" or cmd == "LS" or cmd == "DIR":
            if not authenticated:
                return "530 Please login with USER and PASS"
            
            # Lista ficheiros do diretório atual
            listing = self.generate_file_listing()
            # Retorna imediatamente a listagem (sem conexão de dados real)
            return f"150 Here comes the directory listing\r\n{listing}\r\n226 Directory send OK"
        
        elif cmd == "RETR":
            if not authenticated:
                return "530 Please login with USER and PASS"
            return "550 Permission denied"
        
        elif cmd == "STOR":
            if not authenticated:
                return "530 Please login with USER and PASS"
            return "553 Requested action not taken"
        
        elif cmd == "NOOP":
            return "200 NOOP command successful"
        
        elif cmd == "QUIT":
            return "221 Goodbye"
        
        else:
            return f"500 '{cmd}': command not understood"
    
    def check_credentials(self, username: str, password: str) -> bool:
        """Verifica credenciais"""
        if username == "anonymous" and self.anonymous_login:
            return True
        return self.users.get(username) == password
    
    def generate_file_listing(self) -> str:
        """Gera listagem realista de ficheiros"""
        files = [
            "drwxr-xr-x   3 ftp      ftp          4096 Dec 15 10:23 pub",
            "drwxr-xr-x   2 ftp      ftp          4096 Nov 28 14:11 incoming",
            "drwxr-xr-x   5 root     root         4096 Oct 12 08:45 backups",
            "-rw-r--r--   1 ftp      ftp          2341 Dec 20 16:32 README.txt",
            "-rw-r--r--   1 ftp      ftp         45821 Dec 18 09:14 report_2024.pdf",
            "-rw-r--r--   1 ftp      ftp          8192 Dec 10 11:05 config.ini",
            "-rwxr-xr-x   1 root     ftp         12288 Nov 30 13:22 setup.sh",
            "drwx------   2 admin    admin        4096 Dec 01 10:00 private",
        ]
        return "\r\n".join(files)