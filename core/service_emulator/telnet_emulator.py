"""
Emulador de servidor Telnet
"""
import asyncio
import random
from typing import Dict, Any
from .base_service import BaseService

class TelnetService(BaseService):
    """Emula um servidor Telnet - apenas aceita conexão mas não permite login"""
    
    def __init__(self, port: int, config: Dict[str, Any]):
        super().__init__(port, config)
        self.name = "Telnet Server"
        self.banner = config.get('banner', 'Ubuntu 18.04.6 LTS')
        
    async def handle_connection(self, reader, writer):
        """Manipula conexão Telnet"""
        client_ip = writer.get_extra_info('peername')[0]
        self.log_connection(client_ip)
        
        try:
            # Banner inicial
            await self.send_line(writer, f"\r\n{self.banner}\r\n")
            await self.send_line(writer, "login: ")
            
            # Lê username
            username_data = await asyncio.wait_for(reader.readline(), timeout=30.0)
            username = username_data.decode('utf-8', errors='ignore').strip()
            
            if username:
                self.log_command(client_ip, f"LOGIN_ATTEMPT: {username}")
                
                # Pede password
                await self.send_line(writer, "Password: ")
                password_data = await asyncio.wait_for(reader.readline(), timeout=30.0)
                password = password_data.decode('utf-8', errors='ignore').strip()
                
                self.log_command(client_ip, f"PASSWORD: {password}")
                
                # Sempre rejeita
                await asyncio.sleep(random.uniform(0.5, 1.5))
                await self.send_line(writer, "\r\nLogin incorrect\r\n")
                
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            self.logger.error(f"Telnet error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
    async def send_line(self, writer, text: str):
        """Envia linha para o cliente"""
        writer.write(text.encode('utf-8'))
        await writer.drain()

