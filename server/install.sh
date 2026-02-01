#!/bin/bash

# ============================================
# Скрипт установки 3proxy на Ubuntu 22.04
# ============================================

set -e

echo "=== Установка 3proxy ==="

# Обновляем систему
apt update && apt upgrade -y

# Устанавливаем необходимые пакеты
apt install -y build-essential git

# Скачиваем и компилируем 3proxy
cd /opt
git clone https://github.com/3proxy/3proxy.git
cd 3proxy
make -f Makefile.Linux
make -f Makefile.Linux install

# Создаём директории
mkdir -p /etc/3proxy
mkdir -p /var/log/3proxy

# Генерируем пароль для прокси
PROXY_PASSWORD=$(openssl rand -base64 12)
echo "Сгенерированный пароль для прокси: $PROXY_PASSWORD"

# Создаём конфигурацию
cat > /etc/3proxy/3proxy.cfg << 'EOF'
# 3proxy configuration

# Запуск от пользователя
daemon

# Логирование
log /var/log/3proxy/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"

# DNS серверы
nserver 8.8.8.8
nserver 1.1.1.1
nserver 8.8.4.4

# Таймауты
timeouts 1 5 30 60 180 1800 15 60

# Авторизация
users smartproxy:CL:PROXY_PASSWORD_PLACEHOLDER

# Правила доступа
auth strong
allow smartproxy

# SOCKS5 прокси на порту 18388
socks -p18388
EOF

# Заменяем плейсхолдер на реальный пароль
sed -i "s/PROXY_PASSWORD_PLACEHOLDER/$PROXY_PASSWORD/" /etc/3proxy/3proxy.cfg

# Создаём systemd сервис
cat > /etc/systemd/system/3proxy.service << 'EOF'
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Настраиваем файрвол
ufw allow 18388/tcp
ufw allow 22/tcp
ufw --force enable

# Запускаем сервис
systemctl daemon-reload
systemctl enable 3proxy
systemctl start 3proxy

# Проверяем статус
systemctl status 3proxy

echo ""
echo "=== Установка завершена! ==="
echo ""
echo "Данные для подключения:"
echo "  Сервер: 193.242.109.75"
echo "  Порт: 18388"
echo "  Тип: SOCKS5"
echo "  Пользователь: smartproxy"
echo "  Пароль: $PROXY_PASSWORD"
echo ""
echo "Сохраните пароль! Он понадобится для клиента."
echo ""
echo "Проверка работы:"
echo "  curl --socks5-hostname smartproxy:$PROXY_PASSWORD@193.242.109.75:18388 https://api.ipify.org"
