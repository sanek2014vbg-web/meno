# Security Policy — MeNo Messenger

## 1. Сообщение об уязвимостях (Vulnerability Disclosure)

**Не публикуйте уязвимости в публичных issues.**

| Канал | Использование |
|---|---|
| [GitHub Security Advisories → Report a vulnerability](https://github.com/MeNo-Messenger/meno/security/advisories/new) | **Основной канал.** Приватный отчёт, CVE-координация |
| security@meno.dev | Резервный канал (PGP-ключ — по запросу в advisory) |

### Что включить в отчёт
1. Описание и класс уязвимости (OWASP/CWE), затронутый компонент (`server/`, `client/`).
2. Версию/коммит (`git rev-parse HEAD`) и конфигурацию (dev/staging/prod).
3. Пошаговый воспроизводимый сценарий (PoC-код или curl-запросы желательны).
4. Оценка влияния и предложение по исправлению (опционально).

### SLAM-таймлайны (Severity / Acknowledgement / Fix)
| Уровень | Подтверждение | Патч |
|---|---|---|
| P0 (RCE, компрометация данных, обход аутентификации) | 24 часа | 72 часа |
| P1 (SSRF, XSS с привилегиями, утечка метаданных) | 3 дня | 2 недели |
| P2/P3 (hardening, info disclosure низкого риска) | 7 дней | следующий релиз |

Мы сообщаем статус в течение указанных сроков, публикуем advisory + release notes
после выпуска патча и благодарим исследователей в разделе acknowledgements.

## 2. Защита секретов в репозитории (запрет P0)

- Секреты **не хранятся в git**: `.env*` (кроме `.env.example`), `*.db`, `*.log`,
  `.venv/`, ключи клиента — в `.gitignore`.
- Двойной контроль: pre-commit хук **gitleaks** + job `security` в CI (полное сканирование истории).
- История репозитория очищена `git filter-repo`; все ранее попадавшие в историю
  значения считаются **скомпрометированными** и подлежат ротации (раздел 3).

## 3. Аварийная ротация JWT_SECRET и мастер-ключей на VPS

Триггеры: утечка `.env`, увольнение администратора с доступом, подозрение на
компрометацию, плановая ротация (рекомендуется каждые 90 дней).

**Последствия:** инвалидация всех access/refresh токенов — пользователи будут
перелогинены; подписанные URL файлов станут недействительны. Выполнять окном
обслуживания.

### Шаг 1. Подготовка (на локальной машине)
```bash
# Новый уникальный JWT-секрет (256+ бит энтропии)
python -c "import secrets; print('MENO_JWT_SECRET=' + secrets.token_urlsafe(48))"

# Новые пароли инфраструктуры
openssl rand -base64 24   # MENO_PG_PASSWORD
openssl rand -base64 24   # MINIO_ROOT_PASSWORD (если включён профиль MinIO)
```

### Шаг 2. SSH на VPS и бэкап текущего состояния
```bash
ssh admin@$VPS_HOST
cd /opt/meno
sudo cp .env .env.bak.$(date +%Y%m%d%H%M) && sudo chmod 600 .env.bak.*
docker compose ps                       # фиксация текущего состояния стека
```

### Шаг 3. Ротация PostgreSQL
```bash
# Пароль приложения в БД
docker compose exec db psql -U meno_user -d meno_db -c \
  "ALTER USER meno_user WITH PASSWORD '<НОВЫЙ_MENO_PG_PASSWORD>';"
```

### Шаг 4. Обновление .env (атомарно)
```bash
sudo nano .env
# заменить:
#   MENO_JWT_SECRET=<новый секрет>
#   MENO_PG_PASSWORD=<новый пароль PG>
#   MINIO_ROOT_PASSWORD=<новый, если MinIO используется>
sudo chmod 600 .env
```

### Шаг 5. Перезапуск стека в правильном порядке
```bash
docker compose up -d --force-recreate db redis minio   # инфраструктура принимает новые креды
docker compose up -d --force-recreate app              # приложение стартует с новым JWT_SECRET
# Валидация: сервер отказывается стартовать при пустом/дефолтном секрете —
# это ожидаемое поведение hard-fail валидации конфига.
docker compose logs app --tail 50
curl -fsS http://localhost:8000/health
```

### Шаг 6. Принудительный отзыв всех сессий (defense-in-depth)
Новый JWT_SECRET уже ломает подпись старых токенов, но для явного аудита:
```bash
docker compose exec db psql -U meno_user -d meno_db -c \
  "UPDATE refresh_sessions SET revoked_at = now() WHERE revoked_at IS NULL;"
```
Все события пишутся в `security_events` (audit log) — убедитесь, что запись идёт:
```bash
docker compose exec db psql -U meno_user -d meno_db -c \
  "SELECT event_type, count(*) FROM security_events GROUP BY 1 ORDER BY 2 DESC LIMIT 10;"
```

### Шаг 7. Клиентские мастер-ключи (E2EE)
Серверные ротации достаточно — приватные ключи E2EE живут только на устройствах
(keyring / Android Keystore). При компрометации **сервера** переписка защищена E2EE;
при компрометации **устройства** пользователь в клиенте выполняет «Reset encryption
keys»: генерируется новая пара X25519, старые исходящие ключи помечаются невалидными,
контакты получают предупреждение о смене safety number.

### Шаг 8. Закрытие инцидента
```bash
# Убедиться, что новый секрет нигде не засветился
gitleaks detect --source . --redact
# Уничтожить старый бэкап .env после стабилизации (24–48 ч)
sudo shred -u .env.bak.<старая_дата>
# Зафиксировать инцидент в RUNBOOK/deploy/incidents.md
```

## 4. Обязательные требования production-конфигурации

- `MENO_JWT_SECRET` — уникален, ≥64 символов, не из `.env.example` (иначе boot fail).
- `MENO_ENV=production` — включает strict CORS (белый список origin), HSTS за TLS-терминатором.
- Redis с `requirepass` в multi-tenant окружениях; порты 5432/6379/9000 не публикуются наружу
  (bind 127.0.0.1 или internal network compose).
- Rate limiting активен (Redis-backed); лимиты настраиваются через `MENO_RATE_*`.
- Файлы загрузки: приватный bucket MinIO/S3, доступ только через подписанные URL.

## 5. Supported versions

| Ветка | Статус |
|---|---|
| `main` | ✅ активная разработка, security-патчи немедленно |
| последние теги releases | ✅ патчи до выхода следующей stable |

Обнаружили секрет в открытом issue/PR? Немедленно пишите в advisory — мы удалим
комментарий и ротарируем значение.
