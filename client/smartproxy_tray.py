#!/usr/bin/env python3
"""
SmartProxy с иконкой в системном трее
Для работы в фоновом режиме на Windows
"""

import threading
import sys
import os

# Проверяем наличие pystray (опционально)
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("Модуль pystray не установлен. Запуск в консольном режиме.")
    print("Для установки: pip install pystray pillow")
    print()

from smartproxy import Config, SmartProxyServer, logger


def create_icon_image(color='green'):
    """Создать иконку для трея"""
    # Создаём простую круглую иконку
    size = 64
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    if color == 'green':
        fill_color = (34, 197, 94)  # Зелёный
    elif color == 'yellow':
        fill_color = (234, 179, 8)  # Жёлтый
    else:
        fill_color = (239, 68, 68)  # Красный
    
    # Рисуем круг
    padding = 4
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=fill_color,
        outline=(255, 255, 255)
    )
    
    # Рисуем букву S
    draw.text((size//2 - 8, size//2 - 12), "S", fill=(255, 255, 255))
    
    return image


class SmartProxyTray:
    """SmartProxy с системным треем"""
    
    def __init__(self):
        self.config = None
        self.server = None
        self.server_thread = None
        self.icon = None
        self.running = False
    
    def load_config(self):
        """Загрузить конфигурацию"""
        try:
            self.config = Config()
            return True
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
            return False
    
    def start_server(self):
        """Запустить прокси сервер в отдельном потоке"""
        if self.server and self.server.running:
            return
        
        self.server = SmartProxyServer(self.config)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        self.running = True
        
        if self.icon:
            self.icon.icon = create_icon_image('green')
    
    def stop_server(self):
        """Остановить прокси сервер"""
        if self.server:
            self.server.stop()
            self.running = False
        
        if self.icon:
            self.icon.icon = create_icon_image('red')
    
    def on_toggle(self, icon, item):
        """Включить/выключить прокси"""
        if self.running:
            self.stop_server()
            logger.info("Прокси остановлен")
        else:
            self.start_server()
            logger.info("Прокси запущен")
    
    def on_status(self, icon, item):
        """Показать статус"""
        if self.running:
            logger.info(f"Статус: Работает на {self.config.local_host}:{self.config.local_port}")
        else:
            logger.info("Статус: Остановлен")
    
    def on_quit(self, icon, item):
        """Выход из программы"""
        self.stop_server()
        icon.stop()
    
    def get_toggle_text(self, item):
        """Текст для кнопки переключения"""
        return "Остановить" if self.running else "Запустить"
    
    def run_tray(self):
        """Запустить с иконкой в трее"""
        if not TRAY_AVAILABLE:
            # Запуск в консольном режиме
            self.run_console()
            return
        
        # Создаём меню
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: self.get_toggle_text(item),
                self.on_toggle
            ),
            pystray.MenuItem("Статус", self.on_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", self.on_quit)
        )
        
        # Создаём иконку
        self.icon = pystray.Icon(
            "SmartProxy",
            create_icon_image('yellow'),
            "SmartProxy",
            menu
        )
        
        # Запускаем сервер при старте
        self.start_server()
        
        # Запускаем трей
        logger.info("SmartProxy работает в системном трее")
        logger.info("Кликните правой кнопкой на иконку для меню")
        self.icon.run()
    
    def run_console(self):
        """Запустить в консольном режиме"""
        self.server = SmartProxyServer(self.config)
        try:
            self.server.start()
        except KeyboardInterrupt:
            pass
        finally:
            self.server.stop()


def main():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║          SmartProxy v1.0 (Tray)                  ║")
    print("║   Умный прокси для обхода блокировок             ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    
    app = SmartProxyTray()
    
    if not app.load_config():
        input("Нажмите Enter для выхода...")
        sys.exit(1)
    
    # Проверяем аргументы командной строки
    if '--console' in sys.argv or not TRAY_AVAILABLE:
        app.run_console()
    else:
        app.run_tray()


if __name__ == '__main__':
    main()
