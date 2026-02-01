#!/usr/bin/env python3
"""
SmartProxy - Умный прокси для обхода блокировок
Направляет трафик выбранных сайтов через удалённый SOCKS5 прокси
"""

import socket
import threading
import select
import fnmatch
import logging
import sys
import os
import struct
from pathlib import Path

import yaml

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
            # Ищем config.yaml рядом с исполняемым файлом
            if getattr(sys, 'frozen', False):
                # Запущено как .exe
                base_path = Path(sys.executable).parent
            else:
                # Запущено как .py скрипт
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
        
        logger.info(f"Конфигурация загружена: {len(self.domains)} доменов для проксирования")


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
            # Подключаемся к прокси
            sock.connect((self.proxy_host, self.proxy_port))
            
            # SOCKS5 приветствие
            if self.username and self.password:
                # Аутентификация по логину/паролю
                sock.send(b'\x05\x02\x00\x02')  # 2 метода: без аутентификации и по паролю
            else:
                sock.send(b'\x05\x01\x00')  # 1 метод: без аутентификации
            
            response = sock.recv(2)
            if len(response) < 2:
                raise Exception("Ошибка SOCKS5: нет ответа от прокси")
            
            if response[0] != 0x05:
                raise Exception("Ошибка SOCKS5: неверная версия протокола")
            
            auth_method = response[1]
            
            if auth_method == 0x02:
                # Нужна аутентификация
                auth_packet = bytes([0x01, len(self.username)]) + self.username.encode()
                auth_packet += bytes([len(self.password)]) + self.password.encode()
                sock.send(auth_packet)
                
                auth_response = sock.recv(2)
                if len(auth_response) < 2 or auth_response[1] != 0x00:
                    raise Exception("Ошибка SOCKS5: аутентификация не удалась")
            
            elif auth_method == 0xFF:
                raise Exception("Ошибка SOCKS5: нет подходящего метода аутентификации")
            
            # Запрос на подключение
            # VER CMD RSV ATYP DST.ADDR DST.PORT
            request = b'\x05\x01\x00\x03'  # SOCKS5, CONNECT, RSV, тип адреса: домен
            request += bytes([len(target_host)]) + target_host.encode()
            request += struct.pack('>H', target_port)
            sock.send(request)
            
            # Читаем ответ
            response = sock.recv(4)
            if len(response) < 4:
                raise Exception("Ошибка SOCKS5: неполный ответ")
            
            if response[1] != 0x00:
                error_codes = {
                    0x01: "Общая ошибка SOCKS сервера",
                    0x02: "Соединение запрещено правилами",
                    0x03: "Сеть недоступна",
                    0x04: "Хост недоступен",
                    0x05: "Соединение отклонено",
                    0x06: "TTL истёк",
                    0x07: "Команда не поддерживается",
                    0x08: "Тип адреса не поддерживается",
                }
                error = error_codes.get(response[1], f"Неизвестная ошибка {response[1]}")
                raise Exception(f"Ошибка SOCKS5: {error}")
            
            # Пропускаем адрес в ответе
            atyp = response[3]
            if atyp == 0x01:  # IPv4
                sock.recv(4 + 2)
            elif atyp == 0x03:  # Domain
                domain_len = sock.recv(1)[0]
                sock.recv(domain_len + 2)
            elif atyp == 0x04:  # IPv6
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
            config.proxy_host,
            config.proxy_port,
            config.proxy_user,
            config.proxy_pass
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
            # Проверяем также без wildcard в начале
            if pattern.startswith('*.') and host.endswith(pattern[1:]):
                return True
            if host == pattern:
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
        
        if use_proxy:
            logger.info(f"🔒 PROXY: {host}:{port}")
            try:
                remote_socket = self.socks_client.connect(host, port)
            except Exception as e:
                logger.error(f"Ошибка подключения через прокси к {host}: {e}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
        else:
            logger.debug(f"🌐 DIRECT: {host}:{port}")
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(30)
                remote_socket.connect((host, port))
                remote_socket.settimeout(None)
            except Exception as e:
                logger.error(f"Ошибка прямого подключения к {host}: {e}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
        
        # Отправляем успешный ответ клиенту
        client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        
        # Запускаем двустороннюю передачу данных
        thread1 = threading.Thread(target=self.relay_data, args=(client_socket, remote_socket))
        thread2 = threading.Thread(target=self.relay_data, args=(remote_socket, client_socket))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        try:
            client_socket.close()
        except:
            pass
        try:
            remote_socket.close()
        except:
            pass
    
    def handle_http(self, client_socket: socket.socket, method: str, url: str, headers: bytes):
        """Обработка обычных HTTP запросов"""
        # Извлекаем хост из URL
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
        
        if use_proxy:
            logger.info(f"🔒 PROXY HTTP: {host}:{port}")
            try:
                remote_socket = self.socks_client.connect(host, port)
            except Exception as e:
                logger.error(f"Ошибка подключения через прокси к {host}: {e}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
        else:
            logger.debug(f"🌐 DIRECT HTTP: {host}:{port}")
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(30)
                remote_socket.connect((host, port))
                remote_socket.settimeout(None)
            except Exception as e:
                logger.error(f"Ошибка прямого подключения к {host}: {e}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
        
        # Формируем запрос для удалённого сервера
        request = f'{method} {path} HTTP/1.1\r\n'.encode()
        request += headers
        remote_socket.sendall(request)
        
        # Передаём ответ клиенту
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
        except:
            pass
        try:
            remote_socket.close()
        except:
            pass
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Обработка подключения клиента"""
        try:
            # Читаем первую строку запроса
            data = b''
            while b'\r\n' not in data:
                chunk = client_socket.recv(1024)
                if not chunk:
                    client_socket.close()
                    return
                data += chunk
            
            # Читаем все заголовки
            while b'\r\n\r\n' not in data:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                data += chunk
            
            # Парсим первую строку
            first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            parts = first_line.split(' ')
            
            if len(parts) < 2:
                client_socket.close()
                return
            
            method = parts[0]
            target = parts[1]
            
            # Получаем заголовки (после первой строки)
            headers_start = data.find(b'\r\n') + 2
            headers = data[headers_start:]
            
            if method == 'CONNECT':
                # HTTPS запрос
                if ':' in target:
                    host, port = target.split(':')
                    port = int(port)
                else:
                    host = target
                    port = 443
                
                self.handle_connect(client_socket, host, port)
            else:
                # HTTP запрос
                self.handle_http(client_socket, method, target, headers)
                
        except Exception as e:
            logger.error(f"Ошибка обработки клиента: {e}")
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
            logger.error(f"Не удалось запустить сервер на {self.config.local_host}:{self.config.local_port}")
            logger.error(f"Ошибка: {e}")
            logger.error("Возможно, порт уже занят другой программой")
            return False
        
        self.server_socket.listen(100)
        self.running = True
        
        logger.info("=" * 50)
        logger.info("SmartProxy запущен!")
        logger.info(f"Локальный адрес: http://{self.config.local_host}:{self.config.local_port}")
        logger.info(f"Удалённый прокси: {self.config.proxy_host}:{self.config.proxy_port}")
        logger.info(f"Проксируемых доменов: {len(self.config.domains)}")
        logger.info("=" * 50)
        logger.info("")
        logger.info("Настройте ваш браузер:")
        logger.info(f"  Прокси: {self.config.local_host}")
        logger.info(f"  Порт: {self.config.local_port}")
        logger.info("")
        logger.info("Нажмите Ctrl+C для остановки")
        logger.info("")
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                logger.info("Остановка сервера...")
                break
            except Exception as e:
                if self.running:
                    logger.error(f"Ошибка принятия соединения: {e}")
        
        return True
    
    def stop(self):
        """Остановить прокси сервер"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


def main():
    """Главная функция"""
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║          SmartProxy v1.0                         ║")
    print("║   Умный прокси для обхода блокировок             ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    
    try:
        config = Config()
    except FileNotFoundError as e:
        logger.error(str(e))
        logger.error("Создайте файл config.yaml рядом с программой")
        input("Нажмите Enter для выхода...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Ошибка загрузки конфигурации: {e}")
        input("Нажмите Enter для выхода...")
        sys.exit(1)
    
    # Проверяем подключение к удалённому прокси
    logger.info("Проверка подключения к удалённому прокси...")
    socks = SOCKS5Client(
        config.proxy_host,
        config.proxy_port,
        config.proxy_user,
        config.proxy_pass
    )
    
    try:
        test_sock = socks.connect("api.ipify.org", 80)
        test_sock.send(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        response = test_sock.recv(4096)
        test_sock.close()
        
        # Извлекаем IP из ответа
        if b'\r\n\r\n' in response:
            ip = response.split(b'\r\n\r\n')[1].decode().strip()
            logger.info(f"✓ Подключение успешно! Внешний IP через прокси: {ip}")
        else:
            logger.info("✓ Подключение успешно!")
    except Exception as e:
        logger.error(f"✗ Ошибка подключения к прокси: {e}")
        logger.error("Проверьте настройки в config.yaml")
        input("Нажмите Enter для выхода...")
        sys.exit(1)
    
    # Запускаем сервер
    server = SmartProxyServer(config)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        logger.info("SmartProxy остановлен")


if __name__ == '__main__':
    main()
