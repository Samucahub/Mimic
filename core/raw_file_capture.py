"""
Sistema de captura de arquivos para múltiplos protocolos
Captura uploads via SCP, SFTP, Rsync e conexões TCP brutas
"""

import asyncio
import asyncssh
import socket
import threading
from pathlib import Path
from datetime import datetime
import json
import hashlib


import asyncio
import asyncssh
import socket
import threading
from pathlib import Path
from datetime import datetime
import json
import hashlib


class SCPSFTPServer(asyncssh.SSHServer):
    """Servidor SSH dedicado para captura de SCP/SFTP"""
    
    def __init__(self, capture_dir: Path):
        self.capture_dir = capture_dir
        
    def connection_made(self, conn):
        self.conn = conn
        self.client_ip = conn.get_extra_info('peername')[0]
        print(f"[SCP/SFTP] Connection from {self.client_ip}")
    
    def password_auth_supported(self):
        return True
    
    def validate_password(self, username, password):
        # Aceita qualquer login
        self.username = username
        self.password = password
        print(f"[SCP/SFTP] Login: {username} from {self.client_ip}")
        return True
    
    def session_requested(self):
        return SCPSFTPSession(self.client_ip, self.username, self.capture_dir)
    
    def server_requested(self, listen_host, listen_port):
        return False


class SCPSFTPSession(asyncssh.SSHServerSession):
    """Sessão SSH para captura de SCP"""
    
    def __init__(self, client_ip: str, username: str, capture_dir: Path):
        self.client_ip = client_ip
        self.username = username
        self.capture_dir = capture_dir
        self.scp_mode = False
        self.scp_buffer = bytearray()
        self.scp_filename = None
        self.scp_filesize = 0
        self.scp_received = 0
        
    def connection_made(self, chan):
        self._chan = chan
    
    def shell_requested(self):
        # Não permitir shell interativo
        return False
    
    def exec_requested(self, command):
        """Captura comandos SCP"""
        print(f"[SCP] Command: {command}")
        
        if 'scp' in command.lower():
            # Modo upload (-t)
            if '-t' in command:
                print(f"[SCP] Upload mode activated")
                self.scp_mode = True
                # Envia OK para iniciar protocolo
                self._chan.write(b'\x00')
                return True
            # Modo download (-f)
            elif '-f' in command:
                print(f"[SCP] Download mode - not implemented")
                self._chan.write(b'\x01File not found\n')
                return True
        
        return False
    
    def subsystem_requested(self, subsystem):
        """Captura requisições SFTP"""
        if subsystem == 'sftp':
            print(f"[SFTP] Subsystem requested from {self.client_ip}")
            
            # Retorna servidor SFTP
            from core.service_emulator.ssh_emulator import SimpleSFTPServer
            
            def sftp_logger(action, details):
                print(f"[SFTP] {action}: {details}")
            
            return SimpleSFTPServer(self._chan, logger_callback=sftp_logger)
        
        return False
    
    def data_received(self, data, datatype):
        """Recebe dados do protocolo SCP"""
        if not self.scp_mode:
            return
        
        try:
            # Verifica se é comando ou dados
            if len(data) > 0 and data[0] in [ord('C'), ord('D'), ord('T'), ord('E')]:
                # Comando SCP
                command = data.decode('utf-8', errors='ignore').strip()
                print(f"[SCP] Protocol command: {command}")
                
                if command.startswith('C'):
                    # Formato: C0644 tamanho nome_arquivo
                    parts = command.split()
                    if len(parts) >= 3:
                        mode = parts[0][1:]  # Remove 'C'
                        self.scp_filesize = int(parts[1])
                        self.scp_filename = ' '.join(parts[2:])
                        self.scp_received = 0
                        self.scp_buffer = bytearray()
                        
                        print(f"[SCP] Receiving file: {self.scp_filename} ({self.scp_filesize} bytes)")
                        
                        # Envia OK
                        self._chan.write(b'\x00')
                
                elif command.startswith('E'):
                    # Fim do diretório
                    print(f"[SCP] End of directory")
                    self._chan.write(b'\x00')
                
                elif command.startswith('T'):
                    # Timestamp
                    print(f"[SCP] Timestamp command")
                    self._chan.write(b'\x00')
            
            else:
                # Dados do arquivo
                self.scp_buffer.extend(data)
                self.scp_received += len(data)
                
                # Verifica se completou o arquivo
                if self.scp_received >= self.scp_filesize:
                    # Salva o arquivo
                    self._save_scp_file()
                    
                    # Envia OK final
                    self._chan.write(b'\x00')
                    
                    # Reset para próximo arquivo
                    self.scp_buffer = bytearray()
                    self.scp_received = 0
                    self.scp_filename = None
                    self.scp_filesize = 0
        
        except Exception as e:
            print(f"[SCP] Error processing data: {e}")
            import traceback
            traceback.print_exc()
    
    def _save_scp_file(self):
        """Salva arquivo capturado via SCP"""
        try:
            # Diretório por IP
            ip_safe = self.client_ip.replace('.', '_').replace(':', '_')
            ip_dir = self.capture_dir / 'scp' / ip_safe
            ip_dir.mkdir(parents=True, exist_ok=True)
            
            # Nome do arquivo
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = self.scp_filename.split('/')[-1] if self.scp_filename else 'unknown'
            # Remove caracteres perigosos
            safe_filename = safe_filename.replace('..', '_').replace('/', '_').replace('\\', '_')
            
            # Calcula hash
            file_hash = hashlib.sha256(self.scp_buffer).hexdigest()
            
            # Salva arquivo
            file_path = ip_dir / f"{timestamp}_{safe_filename}"
            file_path.write_bytes(self.scp_buffer)
            
            # Salva metadados
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "client_ip": self.client_ip,
                "username": self.username,
                "filename": self.scp_filename,
                "size": len(self.scp_buffer),
                "sha256": file_hash,
                "saved_as": str(file_path)
            }
            
            meta_path = ip_dir / f"{timestamp}_{safe_filename}.meta.json"
            meta_path.write_text(json.dumps(metadata, indent=2))
            
            print(f"\n{'='*80}")
            print(f"[SCP] FILE CAPTURED!")
            print(f"{'='*80}")
            print(f"From: {self.client_ip} ({self.username})")
            print(f"File: {self.scp_filename}")
            print(f"Size: {len(self.scp_buffer):,} bytes")
            print(f"SHA256: {file_hash}")
            print(f"Saved: {file_path}")
            print(f"{'='*80}\n")
            
        except Exception as e:
            print(f"[SCP] Error saving file: {e}")
            import traceback
            traceback.print_exc()


class RawFileCapture:
    """Captura arquivos de múltiplas fontes"""
    
    def __init__(self):
        self.servers = {}
        self.running = False
        self.ssh_servers = {}  # Servidores SSH para SCP/SFTP
        self.host_keys = {}
        
    async def _start_ssh_server(self, port: int, protocol_type: str):
        """Inicia servidor SSH para SCP/SFTP"""
        try:
            capture_dir = Path("logs/file_captures")
            capture_dir.mkdir(parents=True, exist_ok=True)
            
            # Gera ou carrega chave host
            key_path = Path("logs") / f"ssh_host_key_{port}"
            if key_path.exists():
                host_key = asyncssh.read_private_key(str(key_path))
            else:
                host_key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
                key_path.write_bytes(host_key.export_private_key())
            
            self.host_keys[port] = host_key
            
            # Cria servidor SSH
            server = await asyncssh.create_server(
                lambda: SCPSFTPServer(capture_dir),
                '0.0.0.0',
                port,
                server_host_keys=[host_key],
                server_version='OpenSSH_7.6p1',
                reuse_address=True,
                login_timeout=60
            )
            
            self.ssh_servers[port] = server
            protocol_name = protocol_type.upper()
            print(f"[+] Started {protocol_name} capture server on port {port}")
            
        except Exception as e:
            print(f"[-] Failed to start SSH server on port {port}: {e}")
            import traceback
            traceback.print_exc()
    
    def start_all_servers(self, ports: dict):
        """
        Inicia servidores de captura em múltiplas portas
        
        Args:
            ports: Dict {porta: tipo} ex: {2222: 'scp', 2223: 'sftp'}
        """
        self.running = True
        
        # Separa portas SSH (SCP/SFTP) de portas TCP brutas
        ssh_ports = {}
        tcp_ports = {}
        
        for port, protocol_type in ports.items():
            if protocol_type in ['scp', 'sftp']:
                ssh_ports[port] = protocol_type
            else:
                tcp_ports[port] = protocol_type
        
        # Inicia servidores SSH em thread assíncrona separada
        if ssh_ports:
            def run_ssh_servers():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                for port, protocol_type in ssh_ports.items():
                    loop.run_until_complete(self._start_ssh_server(port, protocol_type))
                
                # Mantém o loop rodando
                try:
                    loop.run_forever()
                except:
                    pass
                finally:
                    loop.close()
            
            ssh_thread = threading.Thread(target=run_ssh_servers, daemon=True)
            ssh_thread.start()
        
        # Inicia servidores TCP brutos
        for port, protocol_type in tcp_ports.items():
            try:
                # Cria servidor TCP simples para cada porta
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', port))
                server_socket.listen(5)
                server_socket.settimeout(1.0)  # Timeout para permitir verificação de self.running
                
                self.servers[port] = {
                    'socket': server_socket,
                    'type': protocol_type,
                    'thread': None
                }
                
                # Inicia thread para aceitar conexões
                thread = threading.Thread(
                    target=self._accept_connections,
                    args=(port, protocol_type, server_socket),
                    daemon=True
                )
                thread.start()
                self.servers[port]['thread'] = thread
                
                protocol_name = protocol_type.upper()
                print(f"[+] Started {protocol_name} capture server on port {port}")
                
            except OSError as e:
                if e.errno == 10048:  # Porta já em uso
                    print(f"[-] Port {port} already in use, skipping {protocol_type}")
                else:
                    print(f"[-] Failed to start {protocol_type} on port {port}: {e}")
            except Exception as e:
                print(f"[-] Error starting {protocol_type} on port {port}: {e}")
        
        print("\n[+] All file capture servers started")
        print("[+] Waiting for connections...\n")
    
    def _accept_connections(self, port: int, protocol_type: str, server_socket: socket.socket):
        """Aceita conexões em uma porta específica"""
        while self.running:
            try:
                client_socket, client_address = server_socket.accept()
                client_ip = client_address[0]
                
                print(f"[{protocol_type.upper()}] Connection from {client_ip} on port {port}")
                
                # Cria thread para lidar com o cliente
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_ip, port, protocol_type),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[{protocol_type.upper()}] Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: socket.socket, client_ip: str, port: int, protocol_type: str):
        """Lida com conexão de cliente individual"""
        try:
            # Configura timeout
            client_socket.settimeout(30.0)
            
            # Diretório de captura
            capture_dir = Path("logs/file_captures") / protocol_type
            capture_dir.mkdir(parents=True, exist_ok=True)
            
            # Diretório por IP
            ip_safe = client_ip.replace('.', '_').replace(':', '_')
            ip_dir = capture_dir / ip_safe
            ip_dir.mkdir(exist_ok=True)
            
            # Recebe dados
            data_buffer = bytearray()
            total_received = 0
            
            while True:
                try:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        break
                    
                    data_buffer.extend(chunk)
                    total_received += len(chunk)
                    
                    # Limite de 100MB por sessão
                    if total_received > 100 * 1024 * 1024:
                        print(f"[{protocol_type.upper()}] Max size exceeded from {client_ip}")
                        break
                        
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[{protocol_type.upper()}] Error receiving data: {e}")
                    break
            
            # Salva dados se recebeu algo
            if len(data_buffer) > 0:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                
                # Salva arquivo bruto
                raw_file = ip_dir / f"{timestamp}_raw.bin"
                raw_file.write_bytes(data_buffer)
                
                # Salva metadados
                metadata = {
                    "timestamp": datetime.now().isoformat(),
                    "client_ip": client_ip,
                    "port": port,
                    "protocol": protocol_type,
                    "size": len(data_buffer),
                    "raw_file": str(raw_file)
                }
                
                meta_file = ip_dir / f"{timestamp}_meta.json"
                with open(meta_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                print(f"[{protocol_type.upper()}] Captured {len(data_buffer)} bytes from {client_ip}")
                print(f"[{protocol_type.upper()}] Saved to: {raw_file}")
            else:
                print(f"[{protocol_type.upper()}] No data received from {client_ip}")
            
        except Exception as e:
            print(f"[{protocol_type.upper()}] Error handling client {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def stop(self):
        """Para todos os servidores"""
        self.running = False
        
        # Para servidores SSH
        for port, server in self.ssh_servers.items():
            try:
                server.close()
                print(f"[+] Stopped SSH server on port {port}")
            except:
                pass
        
        # Para servidores TCP
        for port, server_info in self.servers.items():
            try:
                server_info['socket'].close()
                print(f"[+] Stopped TCP server on port {port}")
            except:
                pass
        
        self.ssh_servers.clear()
        self.servers.clear()


if __name__ == "__main__":
    # Teste
    capture = RawFileCapture()
    
    test_ports = {
        2222: "scp",
        2223: "sftp",
        8730: "rsync",
        9000: "raw",
        9001: "raw"
    }
    
    try:
        capture.start_all_servers(test_ports)
        
        print("\nFile capture servers running...")
        print("Press Ctrl+C to stop\n")
        
        # Mantém rodando
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\nStopping servers...")
        capture.stop()
        print("Stopped.")
