# MeNo — безопасный мессенджер (FastAPI + SQLite + Flet)

MeNo — современный мессенджер без рекламы и спама: вход по номеру телефона с кодом,
личные и групповые чаты, исчезающие сообщения (TTL / «просмотр один раз»), медиа,
WebSocket-реалтайм, E2E-шифрование личных чатов (X25519 + AES-GCM),
ПИН-защита чатов и панель владельца DevMode (2FA, мониторинг, модерация).

## Структура

```
meno/
├── server/            # Бэкенд FastAPI + SQLite
│   ├── main.py        # точка входа (uvicorn main:app --port 8000)
│   ├── database.py    # схема SQLite, миграции
│   ├── auth.py        # пароли (bcrypt), JWT, 2FA (TOTP)
│   ├── sms.py         # коды подтверждения (тестовый режим / Telegram)
│   ├── ws_manager.py  # WebSocket-реалтайм
│   ├── routes_*.py    # API: auth, chats, messages, files, admin
│   └── test_api.py, test_devmode.py   # интеграционные тесты
├── client/            # Flet-клиент (Windows/Android/iOS из одного кода)
│   ├── main.py        # запуск приложения
│   ├── api_client.py  # HTTP + WebSocket клиент
│   ├── crypto.py      # E2E (X25519/AES-GCM), ПИН-защита, локальные настройки
│   ├── themes.py      # тёмная/светлая/авто
│   ├── icons_compat.py# совместимость иконок flet 0.85+
│   ├── run_web.py     # изолированный веб-режим без автооткрытия браузера
│   ├── screens/       # auth, verify, chats_list, chat_view, settings, devmode
│   └── assets/        # логотип MeNo
└── deploy/            # деплой на VPS
    ├── setup_vps.sh   # установка Ubuntu: venv + systemd + nginx + HTTPS
    └── meno.service   # systemd-сервис автозапуска
```

## Запуск сервера (локально)

```bash
cd meno/server
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Коды подтверждения (тестовый режим) выводятся в консоль сервера:
`[MeNo TEST] Код для <телефон>: 123456`.

> На проде задайте переменные окружения в `deploy/meno.service`:
> `MENO_JWT_SECRET` (обязательно), `MENO_ADMIN_PHONE` (номер владельца → роль admin),
> опционально `MENO_SMS_MODE=telegram` + `MENO_TG_BOT_TOKEN`.

## Запуск клиента

### Десктоп (окно)

```bash
cd meno/client
pip install -r requirements.txt
flet run main.py
```

### В браузере (удобно для разработки)

```bash
cd meno/client
flet run -w -p 8550 -a assets main.py     # автооткрытие браузера + hot-reload
```

### Изолированный UI-тест без автооткрытия браузера

```bash
cd meno/client
python run_web.py                          # поднимает http://127.0.0.1:8551
# затем открыть http://127.0.0.1:8551 вручную
```

## Тестовые аккаунты (после пересоздания БД)

| Номер          | Пароль | Роль    | Примечание                    |
|----------------|--------|---------|-------------------------------|
| 79990000001    | 1234   | user    | Owner; чат Friend уже создан  |
| 79990000002    | 5678   | user    | Friend                        |
| 79990000003    | 0000   | user    | Intruder                      |
| 79990000004    | 9999   | admin   | Boss; 2FA TOTP включена       |

Для входа под Boss нужен одноразовый код из приложения-аутентификатора
(секрет TOTP можно взять в БД: `SELECT totp_secret FROM users WHERE phone='79990000004'`).

## Тесты

```bash
# 1) Подготовить чистую БД (по желанию) и создать Owner:
python _seed_owner.py            # внутри server/

# 2) Прогнать интеграционные тесты (сервер должен быть запущен):
cd server && python test_api.py       # 14 проверок
cd server && python test_devmode.py   # 11 проверок
# Итого: 25/25 ✅

# 3) E2E-криптография (клиент ↔ сервер):
cd client && python _check_e2e.py     # 10 проверок

# 4) Медиа-цепочка (upload → send image/file → download):
cd client && python _check_media.py
```

## Проверенные функции

- [x] Регистрация по телефону с кодом, JWT-вход, 2FA TOTP для владельца
- [x] Личные и групповые чаты, участники, история
- [x] Сообщения: текст, эмодзи, TTL (исчезающие), «просмотр один раз»
- [x] WebSocket-реалтайм (новые сообщения, удаления, статусы онлайн)
- [x] Загрузка файлов/фото, рендер изображений
- [x] Жалобы и модерация (DevMode)
- [x] E2E-шифрование личных чатов: X25519 + HKDF + AES-GCM, сервер хранит шифротекст
- [x] Темы: тёмная (по умолчанию), светлая, авто; ручной выбор сохраняется
- [x] ПИН-защита чатов (локально), бейдж 🔒, экран разблокировки
- [x] FLAG_SECURE: переключатель блокировки скриншотов в защищённых чатах (Настройки → Приватность)
- [x] DevMode: статистика, модерация жалоб, глобальные настройки

## Деплой на VPS (Oracle Cloud Always Free)

1. Создайте VM по инструкции [`docs/setup-oracle.md`](../docs/setup-oracle.md).
2. Загрузите папку `meno/` на сервер (scp/git).
3. Выполните:

```bash
cd meno/deploy
chmod +x setup_vps.sh
./setup_vps.sh                 # базовая установка + systemd
./setup_vps.sh --https         # (после настройки DOMAIN) nginx + Let's Encrypt
```

После установки:
- Сервис: `systemctl status meno`
- Логи и коды подтверждения: `journalctl -u meno -f`
- Обновление кода: перезалейте файлы в `/opt/meno/server` и `sudo systemctl restart meno`

## Сборка Android APK

```bash
cd meno/client
flet build apk --project meno --company com.meno.app
# Артефакт: build/apk/meno.apk
```

Сервер по умолчанию в приложении — `http://127.0.0.1:8000`; при сборке для телефона
укажите адрес VPS в поле «Адрес сервера» на экране входа (сохраняется локально).

## Боевая отказоустойчивость (production hardening)

### Сервер

- **SQLite в WAL-режиме** (`PRAGMA journal_mode=WAL`) + пул соединений
  с `busy_timeout=5000` — исключены «database is locked» при одновременной
  записи логов и E2E-сообщений.
- **Rate limiting по связке IP+телефон/пользователь** (`rate_limit.py`):
  регистрация, верификация, вход, загрузка файлов и глобальный лимит по IP.
  Связка с IP не блокирует сотни устройств за общим NAT оператора.
- **Санитизированные логи**: access-лог uvicorn отключён, пишется свой лог
  (`meno.access`) без query-строк, тел запросов, паролей, ключей и текстов
  сообщений. Токены WebSocket передаются заголовком `Authorization`,
  а не в URL.
- Все входящие данные валидируются Pydantic (паттерны номеров, длины полей).

### Клиент

- **Retries с экспоненциальной задержкой** (1s → 2s → 4s) во всех HTTP-запросах
  и загрузке файлов — приложение переживает обрывы мобильного интернета.
- **WebSocket авто-переподключение** с экспоненциальным ожиданием (до 30s)
  и мягким статусом «Подключение… / В сети» в шапке приложения;
  позиция скролла чата после восстановления сессии сохраняется.
- **Динамический адрес сервера**: поле «Адрес сервера» в Настройках и на
  экране входа; `ApiClient.reconfigure()` полностью пересоздаёт HTTP-сессию.
- **Изолированное хранилище токенов**: `meno_vault.bin` (AES-GCM,
  устройственный ключ `.meno_key`), отдельно от `meno_data.json`.
- **FLAG_SECURE** работает в нативной Android-сборке; в веб-версии факт
  недоступности логируется без падения приложения.

## Известные особенности flet 0.85.3 / Python 3.14

- Корутины в лямбда-обработчиках не выполняются — всегда используйте
  `self.app.page.run_task(self._метод)` (передавайте **функцию**, а не результат вызова).
- У экранов нет свойства `page` — используйте `self.app.page`.
- Иконки подключаются через `icons_compat.py` (импортируется первым в `main.py`);
  ошибки Pylance про иконки и типы — ложные.
- `FilePicker()` создаётся без аргументов, затем `fp.on_result = self._on_pick`.
- `page.window.prevent_screenshot` отсутствует в 0.85.3 — используется
  try/except в `App.set_screenshot_blocked`.
- После правок нужен полный рестарт процесса Flet (hot-reload кэширует подмодули).
- Для кнопок предпочтителен параметр `content=`; `SegmentedButton` принимает
  `selected=[...]` списком; диалоги — через `page.show_dialog()` / `page.pop_dialog()`.