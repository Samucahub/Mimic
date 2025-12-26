import pygame
import sys
import yaml
import math
import random
import subprocess
import threading
import time
import platform
from pathlib import Path

pygame.init()

COLORS = {
    'bg': (5, 5, 5),
    'bg_alt': (20, 20, 20),
    'white': (255, 255, 255),
    'gray': (130, 130, 130),
    'gray_dark': (50, 50, 50),
    'gray_light': (200, 200, 200),
    'red': (180, 0, 0),
}

WIDTH, HEIGHT = 1400, 900
FPS = 60

class Button:
    def __init__(self, x, y, w, h, text, action=None):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.action = action
        self.hovered = False

    def draw(self, screen, font):
        offset = random.randint(-2, 2) if self.hovered else 0
        r = self.rect.move(offset, offset)

        pygame.draw.rect(screen, COLORS['white'] if self.hovered else COLORS['gray'], r, 3)
        if self.hovered:
            pygame.draw.rect(screen, COLORS['white'], r)

        txt = font.render(self.text, True, COLORS['bg'] if self.hovered else COLORS['white'])
        screen.blit(txt, txt.get_rect(center=r.center))

    def handle_event(self, e):
        if e.type == pygame.MOUSEMOTION:
            self.hovered = self.rect.collidepoint(e.pos)
        if e.type == pygame.MOUSEBUTTONDOWN and self.hovered:
            if self.action:
                self.action()


class InputBox:
    def __init__(self, x, y, w, h, label, default=""):
        self.rect = pygame.Rect(x, y, w, h)
        self.label = label
        self.text = default
        self.active = False

    def draw(self, screen, font):
        label = font.render(self.label, True, COLORS['gray_light'])
        screen.blit(label, (self.rect.x, self.rect.y - 25))

        pygame.draw.rect(screen, COLORS['bg'], self.rect)
        pygame.draw.rect(screen, COLORS['white'] if self.active else COLORS['gray_dark'], self.rect, 2)

        txt = font.render(self.text, True, COLORS['white'])
        screen.blit(txt, (self.rect.x + 8, self.rect.y + 8))

    def handle_event(self, e):
        if e.type == pygame.MOUSEBUTTONDOWN:
            self.active = self.rect.collidepoint(e.pos)
        if e.type == pygame.KEYDOWN and self.active:
            if e.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            elif e.key == pygame.K_RETURN:
                self.active = False
            else:
                if len(self.text) < 30:
                    self.text += e.unicode


class Checkbox:
    def __init__(self, x, y, label, checked=False):
        self.rect = pygame.Rect(x, y, 22, 22)
        self.label = label
        self.checked = checked

    def draw(self, screen, font):
        pygame.draw.rect(screen, COLORS['bg'], self.rect)
        pygame.draw.rect(screen, COLORS['white'], self.rect, 2)

        if self.checked:
            pygame.draw.line(screen, COLORS['white'], self.rect.topleft, self.rect.bottomright, 3)
            pygame.draw.line(screen, COLORS['white'], self.rect.topright, self.rect.bottomleft, 3)

        txt = font.render(self.label, True, COLORS['gray_light'])
        screen.blit(txt, (self.rect.x + 35, self.rect.y - 2))

    def handle_event(self, e):
        if e.type == pygame.MOUSEBUTTONDOWN and self.rect.collidepoint(e.pos):
            self.checked = not self.checked


class ServiceCard:
    def __init__(self, x, y, w, h, name, port, icon, enabled=False):
        self.rect = pygame.Rect(x, y, w, h)
        self.name = name
        self.port = port
        self.icon = icon
        self.enabled = enabled
        self.hovered = False

    def draw(self, screen, font, small):
        offset = random.randint(-2, 2) if self.hovered else 0
        draw_rect = self.rect.move(offset, 0)

        bg = (245, 245, 245) if self.enabled else COLORS['bg_alt']
        fg = COLORS['bg'] if self.enabled else COLORS['white']

        shadow = draw_rect.move(5, 5)
        pygame.draw.rect(screen, (0, 0, 0), shadow)

        pygame.draw.rect(screen, bg, draw_rect)
        pygame.draw.rect(screen, COLORS['white'], draw_rect, 3)

        if not self.enabled:
            screen.set_clip(draw_rect)
            for i in range(-draw_rect.height, draw_rect.width + draw_rect.height, 20):
                start = (draw_rect.x + i, draw_rect.y)
                end = (draw_rect.x + i + draw_rect.height, draw_rect.y + draw_rect.height)
                pygame.draw.line(screen, COLORS['gray_dark'], start, end, 1)
            screen.set_clip(None)

        screen.blit(font.render(self.icon, True, fg), (draw_rect.x + 15, draw_rect.y + 18))
        screen.blit(font.render(self.name, True, fg), (draw_rect.x + 60, draw_rect.y + 15))
        screen.blit(small.render(f":{self.port}", True, COLORS['gray']), (draw_rect.x + 60, draw_rect.y + 45))

        status_x = draw_rect.right - 40
        status_y = draw_rect.centery

        if self.enabled:
            pygame.draw.circle(screen, COLORS['bg'], (status_x, status_y), 10)
            pygame.draw.circle(screen, COLORS['bg'], (status_x, status_y), 6)
        else:
            pygame.draw.line(screen, COLORS['red'], (status_x-8, status_y-8), (status_x+8, status_y+8), 3)
            pygame.draw.line(screen, COLORS['red'], (status_x+8, status_y-8), (status_x-8, status_y+8), 3)

    def handle_event(self, e):
        if e.type == pygame.MOUSEMOTION:
            self.hovered = self.rect.collidepoint(e.pos)
        elif e.type == pygame.MOUSEBUTTONDOWN and self.rect.collidepoint(e.pos):
            self.enabled = not self.enabled


class MimicConfigurator:
    def __init__(self):
        self.screen = pygame.display.set_mode((WIDTH, HEIGHT))
        pygame.display.set_caption("MIMIC — Raise the Curtain")
        self.clock = pygame.time.Clock()
        self.running = True

        self.font_big = pygame.font.Font(None, 80)
        self.font = pygame.font.Font(None, 32)
        self.small = pygame.font.Font(None, 22)

        self.username = InputBox(100, 240, 200, 35, "USERNAME", "admin")
        self.password = InputBox(320, 240, 200, 35, "PASSWORD", "admin123")
        self.hostname = InputBox(540, 240, 240, 35, "HOSTNAME", "stage-server")
        
        self.os_templates = ["Ubuntu", "Debian", "CentOS", "Windows", "Kali"]
        self.selected_os = 0

        self.services = [
            ServiceCard(100, 350, 400, 75, "SSH", "22", "🔑", True),
            ServiceCard(520, 350, 400, 75, "FTP", "21", "📁"),
            ServiceCard(940, 350, 400, 75, "HTTP", "80", "🌐"),
            ServiceCard(100, 440, 400, 75, "TELNET", "23", "💻"),
            ServiceCard(520, 440, 400, 75, "MYSQL", "3306", "🗄️"),
            ServiceCard(940, 440, 400, 75, "RDP", "3389", "🖥️"),
        ]

        self.any_auth = Checkbox(100, 580, "Accept any credentials (honeypot)")
        self.human = Checkbox(100, 620, "Simulate human hesitation")

        self.save_btn = Button(WIDTH - 480, HEIGHT - 80, 140, 50, "SAVE", self.save_config)
        self.start_btn = Button(WIDTH - 320, HEIGHT - 80, 280, 50, "Let the show begin!", self.start)
        
        self.honeypot_process = None
        self.honeypot_running = False
        self.log_messages = []

    def draw_curtains(self):
        for y in range(0, HEIGHT, 20):
            wave = int(math.sin((y + pygame.time.get_ticks()*0.3)*0.02)*6)
            pygame.draw.rect(self.screen, COLORS['gray_dark'], (wave, y, 60, 20))
            pygame.draw.rect(self.screen, COLORS['gray_dark'], (WIDTH-60+wave, y, 60, 20))

    def draw_spotlight(self):
        light = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)
        for r in range(600, 0, -30):
            pygame.draw.circle(light, (255,255,255,4), (WIDTH//2, HEIGHT//2), r)
        self.screen.blit(light, (0,0))

    def draw_eyes(self):
        blink = abs(math.sin(pygame.time.get_ticks()*0.004))*8
        for dx in (-80, 80):
            pygame.draw.ellipse(
                self.screen, COLORS['white'],
                (WIDTH//2+dx-20, 60+blink, 40, 18-blink)
            )

    def draw_header(self):
        title = self.font_big.render("M I M I C", True, COLORS['white'])
        self.screen.blit(title, (50, 40))
        self.draw_eyes()

        sub = self.small.render("Every port is a mask.", True, COLORS['gray_light'])
        self.screen.blit(sub, (50, 105))
    

    
    def draw_logs_screen(self):
        title = self.font_big.render("THE SHOW IS ON", True, COLORS['white'])
        self.screen.blit(title, (50, 40))
        
        subtitle = self.small.render("Honeypot is running. Watching for visitors...", True, COLORS['gray_light'])
        self.screen.blit(subtitle, (50, 105))
        
        log_area = pygame.Rect(60, 160, WIDTH - 120, HEIGHT - 300)
        pygame.draw.rect(self.screen, COLORS['bg_alt'], log_area)
        pygame.draw.rect(self.screen, COLORS['white'], log_area, 2)
        
        logs_title = self.font.render("LIVE ACTIVITY", True, COLORS['white'])
        self.screen.blit(logs_title, (75, 170))
        
        y_offset = 210
        visible_logs = self.log_messages[-15:]
        for msg in visible_logs:
            log_text = self.small.render(msg[:120], True, COLORS['gray_light'])
            self.screen.blit(log_text, (75, y_offset))
            y_offset += 28
        
        close_rect = pygame.Rect(WIDTH//2 - 150, HEIGHT - 100, 300, 60)
        mouse_pos = pygame.mouse.get_pos()
        is_hovered = close_rect.collidepoint(mouse_pos)
        offset = random.randint(-2, 2) if is_hovered else 0
        btn_rect = close_rect.move(offset, offset)
        
        pygame.draw.rect(self.screen, COLORS['white'] if is_hovered else COLORS['gray'], btn_rect, 3)
        if is_hovered:
            pygame.draw.rect(self.screen, COLORS['white'], btn_rect)
        
        txt = self.font.render("Close the curtains", True, COLORS['bg'] if is_hovered else COLORS['white'])
        self.screen.blit(txt, txt.get_rect(center=btn_rect.center))
        
        for e in pygame.event.get():
            if e.type == pygame.QUIT:
                self.stop_honeypot()
                self.running = False
            elif e.type == pygame.MOUSEBUTTONDOWN:
                if close_rect.collidepoint(e.pos):
                    self.stop_honeypot()

    def run(self):
        while self.running:
            if self.honeypot_running:
                for e in pygame.event.get():
                    if e.type == pygame.QUIT:
                        self.stop_honeypot()
                        self.running = False
                
                self.screen.fill(COLORS['bg'])
                self.draw_curtains()
                self.draw_spotlight()
                self.draw_logs_screen()
                pygame.display.flip()
                self.clock.tick(FPS)
                continue
            
            for e in pygame.event.get():
                if e.type == pygame.QUIT:
                    self.running = False
                
                # OS template selector
                if e.type == pygame.MOUSEBUTTONDOWN:
                    for i, os_name in enumerate(self.os_templates):
                        os_btn_rect = pygame.Rect(100 + i * 120, 720, 110, 35)
                        if os_btn_rect.collidepoint(e.pos):
                            self.selected_os = i

                self.username.handle_event(e)
                self.password.handle_event(e)
                self.hostname.handle_event(e)
                for s in self.services:
                    s.handle_event(e)
                self.any_auth.handle_event(e)
                self.human.handle_event(e)
                self.save_btn.handle_event(e)
                self.start_btn.handle_event(e)

            self.screen.fill(COLORS['bg'])
            self.draw_curtains()
            self.draw_spotlight()
            self.draw_header()
            
            if self.honeypot_running:
                self.draw_logs_screen()
                pygame.display.flip()
                self.clock.tick(FPS)
                continue

            identity_label = self.font.render("IDENTITY", True, COLORS['white'])
            self.screen.blit(identity_label, (100, 185))

            self.username.draw(self.screen, self.small)
            self.password.draw(self.screen, self.small)
            self.hostname.draw(self.screen, self.small)

            services_label = self.font.render("SERVICES", True, COLORS['white'])
            self.screen.blit(services_label, (100, 305))
            pygame.draw.line(self.screen, COLORS['gray_dark'], (100, 332), (WIDTH - 100, 332), 1)

            for s in self.services:
                s.draw(self.screen, self.font, self.small)

            options_label = self.font.render("OPTIONS", True, COLORS['white'])
            self.screen.blit(options_label, (100, 535))

            self.any_auth.draw(self.screen, self.small)
            self.human.draw(self.screen, self.small)
            
            os_label = self.font.render("OS TEMPLATE", True, COLORS['white'])
            self.screen.blit(os_label, (100, 675))
            
            mouse_pos = pygame.mouse.get_pos()
            for i, os_name in enumerate(self.os_templates):
                x = 100 + i * 120
                y = 720
                os_btn_rect = pygame.Rect(x, y, 110, 35)
                
                is_selected = (i == self.selected_os)
                is_hovered = os_btn_rect.collidepoint(mouse_pos)
                
                if is_selected:
                    pygame.draw.rect(self.screen, COLORS['white'], os_btn_rect)
                    pygame.draw.rect(self.screen, COLORS['white'], os_btn_rect, 2)
                else:
                    pygame.draw.rect(self.screen, COLORS['gray_dark'], os_btn_rect)
                    pygame.draw.rect(self.screen, COLORS['gray'] if is_hovered else COLORS['gray_dark'], os_btn_rect, 2)
                
                os_text = self.small.render(os_name, True, COLORS['bg'] if is_selected else COLORS['gray_light'])
                text_rect = os_text.get_rect(center=os_btn_rect.center)
                self.screen.blit(os_text, text_rect)

            phrase = random.choice([
                "The stage is set.",
                "The actor is watching.",
                "Silence is also a response.",
                "The system will imitate you."
            ])
            warn = self.small.render(phrase, True, COLORS['gray'])
            self.screen.blit(warn, warn.get_rect(center=(WIDTH//2, HEIGHT-120)))

            self.save_btn.draw(self.screen, self.font)
            self.start_btn.draw(self.screen, self.font)

            pygame.display.flip()
            self.clock.tick(FPS)

        pygame.quit()
        sys.exit()

    def save_config(self):
        config = {
            "system": {
                "username": self.username.text,
                "password": self.password.text,
                "hostname": self.hostname.text,
                "os_template": self.os_templates[self.selected_os]
            },
            "options": {
                "any_auth": self.any_auth.checked,
                "human_patterns": self.human.checked
            },
            "services": {
                s.port: {
                    "type": s.name.lower(),
                    "enabled": s.enabled
                }
                for s in self.services if s.enabled
            }
        }
        Path("config").mkdir(exist_ok=True)
        with open("config/honeypot.yaml", "w") as f:
            yaml.dump(config, f)

    def start(self):
        self.log_messages = ["[MIMIC] Starting honeypot..."]
        self.save_config()
        self.honeypot_running = True
        
        def run_honeypot():
            try:
                import os
                
                log_file_path = "logs/honeypot_output.log"
                Path("logs").mkdir(exist_ok=True)
                log_file = open(log_file_path, "w", encoding='utf-8', errors='replace')
                
                python_exe = sys.executable
                
                self.log_messages.append(f"[INFO] Using Python: {python_exe}")
                self.log_messages.append(f"[INFO] Platform: {platform.system()}")
                
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = 'utf-8'
                
                kwargs = {
                    'stdout': log_file,
                    'stderr': subprocess.STDOUT,
                    'text': True,
                    'bufsize': 1,
                    'env': env
                }
                
                if platform.system() == 'Windows':
                    kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                
                self.honeypot_process = subprocess.Popen([python_exe, "main.py"], **kwargs)
                
                self.log_messages.append("[OK] Honeypot started successfully")
                self.log_messages.append("[WAIT] Watching log file...")
                
                def read_logs():
                    try:
                        time.sleep(1)
                        with open(log_file_path, "r", encoding='utf-8', errors='replace') as f:
                            f.seek(0, 2)
                            while self.honeypot_running:
                                line = f.readline()
                                if line:
                                    timestamp = time.strftime("%H:%M:%S")
                                    clean_line = ''.join(char if ord(char) < 128 else '?' for char in line.strip())
                                    if clean_line:
                                        self.log_messages.append(f"[{timestamp}] {clean_line[:100]}")
                                else:
                                    time.sleep(0.1)
                                    
                                if self.honeypot_process and self.honeypot_process.poll() is not None:
                                    self.log_messages.append("[ERROR] Honeypot stopped unexpectedly")
                                    break
                    except Exception as e:
                        self.log_messages.append(f"[LOG ERROR] {str(e)[:50]}")
                
                log_thread = threading.Thread(target=read_logs, daemon=True)
                log_thread.start()
                
                time.sleep(2)
                if self.honeypot_process.poll() is not None:
                    self.log_messages.append("[ERROR] Honeypot stopped unexpectedly")
                    self.log_messages.append("[ERROR] Check logs/honeypot_output.log for details")
                
            except Exception as e:
                self.log_messages.append(f"[ERROR] {str(e)}")
        
        thread = threading.Thread(target=run_honeypot, daemon=True)
        thread.start()
    
    def stop_honeypot(self):
        if self.honeypot_process:
            self.log_messages.append("[INFO] Stopping honeypot...")
            
            self.honeypot_process.terminate()
            
            try:
                self.honeypot_process.wait(timeout=3)
                self.log_messages.append("[OK] Honeypot stopped")
            except:
                self.log_messages.append("[WARN] Force killing honeypot...")
                self.honeypot_process.kill()
                try:
                    self.honeypot_process.wait(timeout=2)
                    self.log_messages.append("[OK] Honeypot killed")
                except:
                    self.log_messages.append("[ERROR] Could not kill process")
                    
            self.honeypot_process = None
        
        self.log_messages.append("[INFO] Killing processes on honeypot ports...")
        try:
            import os
            import signal
            
            if platform.system() == 'Windows':
                os.system('taskkill /F /FI "WINDOWTITLE eq main.py*" >nul 2>&1')
                
                ports = [21, 22, 23, 80, 3306, 3389]
                for port in ports:
                    result = os.popen(f'netstat -ano | findstr ":{port} "').read()
                    for line in result.split('\n'):
                        if 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = parts[-1]
                                try:
                                    os.system(f'taskkill /F /PID {pid} >nul 2>&1')
                                    self.log_messages.append(f"[OK] Killed process on port {port} (PID: {pid})")
                                except:
                                    pass
            else:
                os.system('pkill -f "main.py" 2>/dev/null')
                
                ports = [21, 22, 23, 80, 3306, 3389]
                for port in ports:
                    result = os.popen(f'lsof -ti:{port} 2>/dev/null').read().strip()
                    if result:
                        for pid in result.split('\n'):
                            if pid:
                                try:
                                    os.kill(int(pid), signal.SIGKILL)
                                    self.log_messages.append(f"[OK] Killed process on port {port} (PID: {pid})")
                                except:
                                    pass
        except Exception as e:
            self.log_messages.append(f"[WARN] Error killing port processes: {str(e)[:50]}")
            
        self.honeypot_running = False
        time.sleep(0.5)


if __name__ == "__main__":
    MimicConfigurator().run()
