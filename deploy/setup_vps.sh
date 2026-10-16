#!/usr/bin/env bash
# ============================================================
# MeNo — развёртывание бэкенда на Ubuntu VPS (Oracle Cloud).
#
# Использование (выполнять от пользователя ubuntu):
#   chmod +x setup_vps.sh
#   ./setup_vps.sh            # базовая установка + systemd
#   ./setup_vps.sh --https    # дополнительно: nginx + HTTPS (Let's Encrypt)
#
# Перед запуском отредактируйте переменные ниже:
#   ADMIN_PHONE  — номер владельца (получит роль admin и DevMode)
#   JWT_SECRET   — длинная случайная строка (пароли/токены)
#   DOMAIN       — домен для HTTPS (например meno.example.com)
# ============================================================
set -euo pipefail

APP_DIR="/opt/meno"
SERVER_DIR="$APP_DIR/server"
VENV_DIR="$APP_DIR/.venv"
SERVICE_USER="meno"

# ---- Переменные для редактирования -------------------------
ADMIN_PHONE="${ADMIN_PHONE:-79990000001}"
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32)}"
DOMAIN="${DOMAIN:-}"          # например "meno.example.com" для --https
HTTPS_MODE="${1:-}"           # "--https" включает nginx+certbot
# ------------------------------------------------------------

echo "==> Обновление системы и установка зависимостей"
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git nginx certbot python3-certbot-nginx ufw

echo "==> Создание пользователя-сервиса $SERVICE_USER"
sudo id -u "$SERVICE_USER" &>/dev/null || sudo useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

echo "==> Копирование кода сервера в $SERVER_DIR"
sudo mkdir -p "$SERVER_DIR"
# Замените источник на ваш репозиторий/копию, например:
#   git clone https://github.com/you/meno.git /tmp/meno && sudo cp -r /tmp/meno/server/. "$SERVER_DIR"/
# Или загрузите файлы по scp:
#   scp -r server/* ubuntu@IP:/tmp/meno-server/
sudo cp -r ../server/. "$SERVER_DIR"/ 2>/dev/null || true

echo "==> Виртуальное окружение и зависимости"
sudo python3 -m venv "$VENV_DIR"
sudo "$VENV_DIR/bin/pip" install --upgrade pip
sudo "$VENV_DIR/bin/pip" install -r "$SERVER_DIR/requirements.txt"

echo "==> Права на каталоги"
sudo mkdir -p "$SERVER_DIR/uploads" "$SERVER_DIR/static"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

echo "==> Настройка окружения в systemd-юните"
sudo sed -i \
  -e "s|ЗАМЕНИТЕ_НА_ДЛИННУЮ_СЛУЧАЙНУЮ_СТРОКУ|$JWT_SECRET|" \
  -e "s|ВАШ_НОМЕР_ВЛАДЕЛЬЦА|$ADMIN_PHONE|" \
  "$APP_DIR/meno.service" 2>/dev/null || true
sudo cp -f meno.service /etc/systemd/system/meno.service

echo "==> Запуск сервиса MeNo"
sudo systemctl daemon-reload
sudo systemctl enable meno
sudo systemctl restart meno
sleep 2
sudo systemctl status meno --no-pager | head -n 12

echo "==> Открываем порт 8000 в UFW"
sudo ufw allow OpenSSH
sudo ufw allow 8000/tcp
sudo ufw --force enable

if [[ "$HTTPS_MODE" == "--https" && -n "$DOMAIN" ]]; then
  echo "==> Настройка nginx как reverse proxy на :443 (HTTPS)"
  sudo tee /etc/nginx/sites-available/meno >/dev/null <<EOF
# Формат лога БЕЗ query-параметров: токены авторизации не попадают в nginx-лог
log_format meno '\$remote_addr - \$request_method \$uri \$status \$body_bytes_sent \$request_time';

upstream meno_backend {
    server 127.0.0.1:8000;
    keepalive 32;   # переиспользование соединений к uvicorn
}

server {
    listen 80;
    server_name $DOMAIN;
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    client_max_body_size 60m;
    access_log /var/log/nginx/meno.access.log meno;

    # API и WebSocket — единый прокси с поддержкой апгрейда
    location / {
        proxy_pass http://meno_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Стабильные WebSocket без обрывов по таймауту
        proxy_buffering off;            # реалтайм: без буферизации ответов
        proxy_read_timeout 3600s;       # долгоживущее WS-соединение
        proxy_send_timeout 3600s;
        proxy_connect_timeout 10s;
        proxy_set_header Connection \$http_connection;  # keepalive для HTTP
    }

    # Заголовки безопасности
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
}
EOF
  sudo ln -sf /etc/nginx/sites-available/meno /etc/nginx/sites-enabled/meno
  sudo nginx -t
  sudo systemctl reload nginx

  echo "==> Выпуск бесплатного сертификата Let's Encrypt"
  sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@"$DOMAIN" --redirect
fi

echo ""
echo "Готово! Бэкенд MeNo работает на http://$(hostname -I | awk '{print $1}'):8000"
[[ -n "$DOMAIN" ]] && echo "HTTPS: https://$DOMAIN"
echo "Коды подтверждения (тестовый режим): journalctl -u meno -f"