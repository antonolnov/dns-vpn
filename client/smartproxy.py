#!/usr/bin/env python3
"""
SmartProxy - Умный прокси для обхода блокировок
Автоматически настраивает систему Windows для проксирования выбранных сайтов
"""

import socket
import threading
import select
import fnmatch
import logging
import sys
import os
import struct
import signal
import atexit
import ctypes
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

import yaml

# Для Windows - работа с реестром и настройками прокси
if sys.platform == 'win32':
    import winreg

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('SmartProxy')


class Config:
    """Класс для работы с конфигурацией"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            if getattr(sys, 'frozen', False):
                base_path = Path(sys.executable).parent
            else:
                base_path = Path(__file__).parent
            config_path = base_path / 'config.yaml'
        
        self.config_path = Path(config_path)
        self.load()
    
    def load(self):
        """Загрузить конфигурацию из файла"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Файл конфигурации не найден: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        # Удалённый прокси
        self.proxy_host = data['proxy']['host']
        self.proxy_port = data['proxy']['port']
        self.proxy_user = data['proxy'].get('username', '')
        self.proxy_pass = data['proxy'].get('password', '')
        
        # Локальный прокси
        self.local_host = data['local']['host']
        self.local_port = data['local']['port']
        
        # Домены для проксирования
        self.domains = data.get('domains', [])
        
        # Логирование
        log_config = data.get('logging', {})
        if log_config.get('enabled', True):
            level = log_config.get('level', 'INFO')
            logger.setLevel(getattr(logging, level))
        
        logger.info(f"Загружено {len(self.domains)} доменов для проксирования")


class WindowsProxyManager:
    """Управление системными настройками прокси в Windows"""
    
    INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    
    def __init__(self):
        self.original_settings = {}
        self.pac_url = None
    
    def save_original_settings(self):
        """Сохранить оригинальные настройки прокси"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_READ)
            
            try:
                self.original_settings['ProxyEnable'], _ = winreg.QueryValueEx(key, 'ProxyEnable')
            except FileNotFoundError:
                self.original_settings['ProxyEnable'] = 0
            
            try:
                self.original_settings['ProxyServer'], _ = winreg.QueryValueEx(key, 'ProxyServer')
            except FileNotFoundError:
                self.original_settings['ProxyServer'] = ''
            
            try:
                self.original_settings['AutoConfigURL'], _ = winreg.QueryValueEx(key, 'AutoConfigURL')
            except FileNotFoundError:
                self.original_settings['AutoConfigURL'] = ''
            
            winreg.CloseKey(key)
            logger.debug(f"Сохранены оригинальные настройки: {self.original_settings}")
        except Exception as e:
            logger.error(f"Ошибка сохранения настроек: {e}")
    
    def set_pac_proxy(self, pac_url: str):
        """Установить PAC-файл как источник настроек прокси"""
        self.pac_url = pac_url
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_WRITE)
            
            # Отключаем ручной прокси
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            
            # Устанавливаем PAC URL
            winreg.SetValueEx(key, 'AutoConfigURL', 0, winreg.REG_SZ, pac_url)
            
            winreg.CloseKey(key)
            
            # Уведомляем систему об изменениях
            self._refresh_settings()
            
            logger.info(f"Системный прокси настроен: {pac_url}")
            return True
        except Exception as e:
            logger.error(f"Ошибка установки прокси: {e}")
            return False
    
    def restore_original_settings(self):
        """Восстановить оригинальные настройки прокси"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS, 0, winreg.KEY_WRITE)
            
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 
                            self.original_settings.get('ProxyEnable', 0))
            
            if self.original_settings.get('ProxyServer'):
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, 
                                self.original_settings['ProxyServer'])
            
            if self.original_settings.get('AutoConfigURL'):
                winreg.SetValueEx(key, 'AutoConfigURL', 0, winreg.REG_SZ, 
                                self.original_settings['AutoConfigURL'])
            else:
                # Удаляем PAC URL
                try:
                    winreg.DeleteValue(key, 'AutoConfigURL')
                except FileNotFoundError:
                    pass
            
            winreg.CloseKey(key)
            
            # Уведомляем систему об изменениях
            self._refresh_settings()
            
            logger.info("Оригинальные настройки прокси восстановлены")
            return True
        except Exception as e:
            logger.error(f"Ошибка восстановления настроек: {e}")
            return False
    
    def _refresh_settings(self):
        """Уведомить Windows об изменении настроек интернета"""
        try:
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception as e:
            logger.debug(f"Не удалось обновить настройки: {e}")


class PACGenerator:
    """Генератор PAC-файла для умной маршрутизации"""
    
    def __init__(self, domains: list, proxy_address: str):
        self.domains = domains
        self.proxy_address = proxy_address
    
    def generate(self) -> str:
        """Сгенерировать PAC-файл"""
        # Группируем домены для оптимизации
        exact_domains = []
        suffix_domains = []
        
        for domain in self.domains:
            domain = domain.lower().strip()
            if domain.startswith('*.'):
                suffix_domains.append(domain[2:])  # убираем *.
            else:
                exact_domains.append(domain)
                # Также добавляем как суффикс для поддоменов
                suffix_domains.append(domain)
        
        # Убираем дубликаты
        exact_domains = list(set(exact_domains))
        suffix_domains = list(set(suffix_domains))
        
        pac_content = f'''function FindProxyForURL(url, host) {{
    // SmartProxy PAC file
    // Проксирует выбранные домены через {self.proxy_address}
    
    host = host.toLowerCase();
    
    // Локальные адреса - всегда напрямую
    if (isPlainHostName(host) ||
        shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.*") ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*")) {{
        return "DIRECT";
    }}
    
    // Список точных доменов
    var exactDomains = {repr(exact_domains)};
    
    // Список суффиксов (для поддоменов)
    var suffixDomains = {repr(suffix_domains)};
    
    // Проверяем точное совпадение
    for (var i = 0; i < exactDomains.length; i++) {{
        if (host === exactDomains[i]) {{
            return "PROXY {self.proxy_address}";
        }}
    }}
    
    // Проверяем суффиксы (поддомены)
    for (var i = 0; i < suffixDomains.length; i++) {{
        if (dnsDomainIs(host, suffixDomains[i]) || 
            host === suffixDomains[i] ||
            shExpMatch(host, "*." + suffixDomains[i])) {{
            return "PROXY {self.proxy_address}";
        }}
    }}
    
    // Всё остальное - напрямую
    return "DIRECT";
}}
'''
        return pac_content


class PACServer(threading.Thread):
    """HTTP сервер для раздачи PAC-файла"""
    
    def __init__(self, host: str, port: int, pac_content: str):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.pac_content = pac_content
        self.server = None
    
    def run(self):
        """Запустить сервер"""
        handler = self._create_handler()
        self.server = HTTPServer((self.host, self.port), handler)
        self.server.serve_forever()
    
    def _create_handler(self):
        """Создать обработчик HTTP запросов"""
        pac_content = self.pac_content
        
        class PACHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/proxy.pac' or self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
                    self.send_header('Content-Length', len(pac_content))
                    self.end_headers()
                    self.wfile.write(pac_content.encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Отключаем логи HTTP сервера
        
        return PACHandler
    
    def stop(self):
        """Остановить сервер"""
        if self.server:
            self.server.shutdown()


class SOCKS5Client:
    """Клиент для подключения через SOCKS5 прокси"""
    
    def __init__(self, proxy_host: str, proxy_port: int, username: str = '', password: str = ''):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
    
    def connect(self, target_host: str, target_port: int) -> socket.socket:
        """Подключиться к целевому хосту через SOCKS5 прокси"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        
        try:
            sock.connect((self.proxy_host, self.proxy_port))
            
            if self.username and self.password:
                sock.send(b'\x05\x02\x00\x02')
            else:
                sock.send(b'\x05\x01\x00')
            
            response = sock.recv(2)
            if len(response) < 2:
                raise Exception("Нет ответа от прокси")
            
            if response[0] != 0x05:
                raise Exception("Неверная версия SOCKS")
            
            auth_method = response[1]
            
            if auth_method == 0x02:
                auth_packet = bytes([0x01, len(self.username)]) + self.username.encode()
                auth_packet += bytes([len(self.password)]) + self.password.encode()
                sock.send(auth_packet)
                
                auth_response = sock.recv(2)
                if len(auth_response) < 2 or auth_response[1] != 0x00:
                    raise Exception("Аутентификация не удалась")
            elif auth_method == 0xFF:
                raise Exception("Нет подходящего метода аутентификации")
            
            request = b'\x05\x01\x00\x03'
            request += bytes([len(target_host)]) + target_host.encode()
            request += struct.pack('>H', target_port)
            sock.send(request)
            
            response = sock.recv(4)
            if len(response) < 4:
                raise Exception("Неполный ответ")
            
            if response[1] != 0x00:
                error_codes = {
                    0x01: "Общая ошибка", 0x02: "Запрещено",
                    0x03: "Сеть недоступна", 0x04: "Хост недоступен",
                    0x05: "Отклонено", 0x06: "TTL истёк",
                }
                raise Exception(error_codes.get(response[1], f"Ошибка {response[1]}"))
            
            atyp = response[3]
            if atyp == 0x01:
                sock.recv(4 + 2)
            elif atyp == 0x03:
                domain_len = sock.recv(1)[0]
                sock.recv(domain_len + 2)
            elif atyp == 0x04:
                sock.recv(16 + 2)
            
            sock.settimeout(None)
            return sock
            
        except Exception as e:
            sock.close()
            raise


class SmartProxyServer:
    """HTTP прокси сервер с умной маршрутизацией"""
    
    def __init__(self, config: Config):
        self.config = config
        self.socks_client = SOCKS5Client(
            config.proxy_host, config.proxy_port,
            config.proxy_user, config.proxy_pass
        )
        self.running = False
        self.server_socket = None
    
    def should_proxy(self, host: str) -> bool:
        """Проверить, нужно ли проксировать данный хост"""
        host = host.lower()
        for pattern in self.config.domains:
            pattern = pattern.lower()
            if fnmatch.fnmatch(host, pattern):
                return True
            if pattern.startswith('*.') and host.endswith(pattern[1:]):
                return True
            if host == pattern:
                return True
            # Проверяем поддомены
            if host.endswith('.' + pattern):
                return True
        return False
    
    def relay_data(self, source: socket.socket, destination: socket.socket):
        """Передача данных между сокетами"""
        try:
            while True:
                data = source.recv(8192)
                if not data:
                    break
                destination.sendall(data)
        except:
            pass
    
    def handle_connect(self, client_socket: socket.socket, host: str, port: int):
        """Обработка CONNECT запроса (HTTPS)"""
        use_proxy = self.should_proxy(host)
        
        try:
            if use_proxy:
                logger.info(f"🔒 PROXY: {host}:{port}")
                remote_socket = self.socks_client.connect(host, port)
            else:
                logger.debug(f"🌐 DIRECT: {host}:{port}")
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(30)
                remote_socket.connect((host, port))
                remote_socket.settimeout(None)
        except Exception as e:
            logger.error(f"Ошибка подключения к {host}: {e}")
            client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            client_socket.close()
            return
        
        client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        
        thread1 = threading.Thread(target=self.relay_data, args=(client_socket, remote_socket), daemon=True)
        thread2 = threading.Thread(target=self.relay_data, args=(remote_socket, client_socket), daemon=True)
        
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        
        try:
            client_socket.close()
            remote_socket.close()
        except:
            pass
    
    def handle_http(self, client_socket: socket.socket, method: str, url: str, headers: bytes):
        """Обработка HTTP запросов"""
        if url.startswith('http://'):
            url = url[7:]
        
        if '/' in url:
            host_port, path = url.split('/', 1)
            path = '/' + path
        else:
            host_port = url
            path = '/'
        
        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 80
        
        use_proxy = self.should_proxy(host)
        
        try:
            if use_proxy:
                logger.info(f"🔒 PROXY HTTP: {host}:{port}")
                remote_socket = self.socks_client.connect(host, port)
            else:
                logger.debug(f"🌐 DIRECT HTTP: {host}:{port}")
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(30)
                remote_socket.connect((host, port))
                remote_socket.settimeout(None)
        except Exception as e:
            logger.error(f"Ошибка подключения к {host}: {e}")
            client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            client_socket.close()
            return
        
        request = f'{method} {path} HTTP/1.1\r\n'.encode() + headers
        remote_socket.sendall(request)
        
        try:
            while True:
                data = remote_socket.recv(8192)
                if not data:
                    break
                client_socket.sendall(data)
        except:
            pass
        
        try:
            client_socket.close()
            remote_socket.close()
        except:
            pass
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Обработка подключения клиента"""
        try:
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = client_socket.recv(4096)
                if not chunk:
                    client_socket.close()
                    return
                data += chunk
            
            first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            parts = first_line.split(' ')
            
            if len(parts) < 2:
                client_socket.close()
                return
            
            method = parts[0]
            target = parts[1]
            headers_start = data.find(b'\r\n') + 2
            headers = data[headers_start:]
            
            if method == 'CONNECT':
                if ':' in target:
                    host, port = target.split(':')
                    port = int(port)
                else:
                    host = target
                    port = 443
                self.handle_connect(client_socket, host, port)
            else:
                self.handle_http(client_socket, method, target, headers)
                
        except Exception as e:
            logger.error(f"Ошибка: {e}")
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Запустить прокси сервер"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.config.local_host, self.config.local_port))
        except OSError as e:
            logger.error(f"Порт {self.config.local_port} занят!")
            return False
        
        self.server_socket.listen(100)
        self.running = True
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                if self.running:
                    logger.error(f"Ошибка: {e}")
        
        return True
    
    def stop(self):
        """Остановить прокси сервер"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class SmartProxyApp:
    """Главное приложение SmartProxy"""
    
    def __init__(self):
        self.config = None
        self.proxy_server = None
        self.pac_server = None
        self.proxy_manager = None
        self.running = False
    
    def setup(self):
        """Настройка приложения"""
        # Загружаем конфигурацию
        try:
            self.config = Config()
        except FileNotFoundError as e:
            logger.error(str(e))
            return False
        except Exception as e:
            logger.error(f"Ошибка конфигурации: {e}")
            return False
        
        # Проверяем подключение к удалённому прокси
        logger.info("Проверка подключения к серверу...")
        socks = SOCKS5Client(
            self.config.proxy_host, self.config.proxy_port,
            self.config.proxy_user, self.config.proxy_pass
        )
        
        try:
            test_sock = socks.connect("api.ipify.org", 80)
            test_sock.send(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            response = test_sock.recv(4096)
            test_sock.close()
            
            if b'\r\n\r\n' in response:
                ip = response.split(b'\r\n\r\n')[1].decode().strip()
                logger.info(f"✓ Сервер доступен! IP: {ip}")
        except Exception as e:
            logger.error(f"✗ Сервер недоступен: {e}")
            return False
        
        return True
    
    def start(self):
        """Запустить приложение"""
        if not self.setup():
            return False
        
        self.running = True
        
        # Создаём PAC-файл
        pac_port = self.config.local_port + 1  # PAC на следующем порту
        proxy_address = f"{self.config.local_host}:{self.config.local_port}"
        
        pac_generator = PACGenerator(self.config.domains, proxy_address)
        pac_content = pac_generator.generate()
        
        # Запускаем PAC-сервер
        self.pac_server = PACServer(self.config.local_host, pac_port, pac_content)
        self.pac_server.start()
        
        pac_url = f"http://{self.config.local_host}:{pac_port}/proxy.pac"
        
        # Настраиваем системный прокси (только для Windows)
        if sys.platform == 'win32':
            self.proxy_manager = WindowsProxyManager()
            self.proxy_manager.save_original_settings()
            self.proxy_manager.set_pac_proxy(pac_url)
            
            # Регистрируем очистку при выходе
            atexit.register(self.cleanup)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Выводим информацию
        print()
        print("=" * 55)
        print("  SmartProxy запущен и работает!")
        print("=" * 55)
        print()
        print(f"  Локальный прокси:  {self.config.local_host}:{self.config.local_port}")
        print(f"  PAC-файл:          {pac_url}")
        print(f"  Удалённый сервер:  {self.config.proxy_host}:{self.config.proxy_port}")
        print(f"  Доменов:           {len(self.config.domains)}")
        print()
        if sys.platform == 'win32':
            print("  ✓ Системный прокси настроен автоматически")
            print("  ✓ Браузеры будут использовать SmartProxy")
        print()
        print("  Проксируемые сайты будут открываться через Латвию")
        print("  Остальные сайты — напрямую")
        print()
        print("  Нажмите Ctrl+C для выхода")
        print("=" * 55)
        print()
        
        # Запускаем прокси-сервер
        self.proxy_server = SmartProxyServer(self.config)
        try:
            self.proxy_server.start()
        except KeyboardInterrupt:
            pass
        
        return True
    
    def _signal_handler(self, signum, frame):
        """Обработчик сигналов"""
        print("\nОстановка...")
        self.stop()
        sys.exit(0)
    
    def cleanup(self):
        """Очистка при выходе"""
        if self.proxy_manager:
            self.proxy_manager.restore_original_settings()
    
    def stop(self):
        """Остановить приложение"""
        self.running = False
        
        if self.proxy_server:
            self.proxy_server.stop()
        
        if self.pac_server:
            self.pac_server.stop()
        
        if self.proxy_manager:
            self.proxy_manager.restore_original_settings()
        
        logger.info("SmartProxy остановлен")


def main():
    print()
    print("╔═══════════════════════════════════════════════════════╗")
    print("║               SmartProxy v1.0                         ║")
    print("║     Умный прокси для обхода блокировок                ║")
    print("║                                                       ║")
    print("║  Автоматически настраивает систему Windows            ║")
    print("║  Никаких расширений в браузере не нужно!              ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    
    # Проверяем права администратора (рекомендуется, но не обязательно)
    if sys.platform == 'win32':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                logger.warning("Рекомендуется запуск от имени администратора")
        except:
            pass
    
    app = SmartProxyApp()
    
    try:
        if not app.start():
            input("\nНажмите Enter для выхода...")
            sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()


if __name__ == '__main__':
    main()
