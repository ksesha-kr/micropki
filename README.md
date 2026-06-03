# MicroPKI
MicroPKI — это легковесный инструмент для создания и управления полной иерархией удостоверяющих центров (Root и Intermediate CA), выпуска сертификатов по шаблонам, проверки их статуса через CRL и OCSP, а также аудита всех операций с криптографической защитой логов.

## Установка

### Требования

- Python 3.10 или выше
- OpenSSL (для верификации и демо)
- pip

### Настройка

```bash
# Клонирование репозитория
git clone https://github.com/ksesha-kr/micropki.git
cd micropki

# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate

# Установка зависимостей
pip install -r requirements.txt

# Установка пакета в режиме разработки
pip install -e .
```

## Быстрый старт

### Запуск демо-сценария

```bash
python demo/demo.py
```

Демо автоматически выполнит:
1. Создание Root и Intermediate CA
2. Выпуск сертификатов (server, client, OCSP)
3. Запуск HTTP репозитория
4. Валидацию цепочки через OpenSSL
5. Генерацию CRL
6. Проверку аудит-логов
7. Демонстрацию политик безопасности

## Использование

### Инициализация корневого CA

```bash
mkdir -p secrets
echo "strong-passphrase" > secrets/root.pass

micropki ca init \
    --subject "/CN=My Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir ./pki \
    --validity-days 3650
```

### Инициализация Intermediate CA

```bash
echo "intermediate-passphrase" > secrets/intermediate.pass

micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=My Intermediate CA" \
    --passphrase-file secrets/intermediate.pass \
    --out-dir ./pki
```

### Выпуск сертификатов

**Серверный сертификат:**
```bash
micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com" \
    --san dns:example.com \
    --san dns:www.example.com \
    --out-dir ./pki/certs
```

**Клиентский сертификат:**
```bash
micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir ./pki/certs
```

### Отзыв сертификата

```bash
# Поиск серийного номера
micropki ca list-certs --format table

# Отзыв
micropki ca revoke 1A2B3C4D --reason keyCompromise --force
```

### Генерация CRL

```bash
micropki ca gen-crl --ca intermediate
```

### Запуск HTTP репозитория

```bash
micropki repo serve --host 0.0.0.0 --port 8080 --rate-limit 10
```

### Запуск OCSP Responder

```bash
# Выпуск OCSP сертификата
micropki ca issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder" \
    --out-dir ./pki/certs

# Запуск OCSP сервера
micropki ocsp serve \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem
```

### Проверка статуса через OCSP

```bash
openssl ocsp \
    -issuer ./pki/certs/intermediate.cert.pem \
    -cert ./pki/certs/example.com.cert.pem \
    -url http://localhost:8081/ocsp \
    -resp_text
```

### Аудит и безопасность

```bash
# Просмотр аудит-логов
micropki audit query --level AUDIT --format table

# Проверка целостности логов
micropki audit verify

# Симуляция компрометации ключа
micropki ca compromise --cert ./pki/certs/example.com.cert.pem

# Проверка CT лога
micropki audit ct-verify --serial 1A2B3C4D
```

## Параметры командной строки

| Параметр | Описание | Обязательный |
|----------|----------|--------------|
| `--subject` | Distinguished Name | Да |
| `--key-type` | `rsa` или `ecc` (по умолчанию: `rsa`) | Нет |
| `--key-size` | Размер ключа: RSA: 2048/4096, ECC: 256/384 | Нет |
| `--passphrase-file` | Путь к файлу с парольной фразой | Да |
| `--out-dir` | Выходная директория (по умолчанию: `./pki`) | Нет |
| `--validity-days` | Срок действия в днях | Нет |
| `--san` | Subject Alternative Name | Для `issue-cert` |
| `--template` | `server`, `client`, `code_signing` | Для `issue-cert` |
| `--rate-limit` | Запросов в секунду на IP | Для `repo serve` |
| `--rate-burst` | Максимальный burst | Для `repo serve` |

---

## Структура проекта

```
micropki/
├── micropki/           # Основной пакет
│   ├── audit.py        # Аудит с hash chain
│   ├── ca.py           # Операции с CA
│   ├── certificates.py # X.509 сертификаты
│   ├── chain.py        # Валидация цепочек
│   ├── cli.py          # CLI интерфейс
│   ├── client.py       # Клиентские команды
│   ├── compromise.py   # Управление компрометацией
│   ├── crl.py          # Генерация CRL
│   ├── crypto_utils.py # Криптоутилиты
│   ├── csr.py          # Работа с CSR
│   ├── database.py     # SQLite
│   ├── ocsp.py         # OCSP протокол
│   ├── ocsp_responder.py # OCSP сервер
│   ├── policy.py       # Политики безопасности
│   ├── ratelimit.py    # Rate limiting
│   ├── repository.py   # HTTP репозиторий
│   ├── revocation.py   # Отзыв сертификатов
│   ├── revocation_check.py # Проверка отзыва
│   ├── serial.py       # Серийные номера
│   ├── templates.py    # Шаблоны сертификатов
│   └── validation.py   # Валидация цепочек
├── demo/               # Демо-скрипты
│   └── demo.py
├── docs/               # Документация
│   ├── api_reference.md
│   ├── architecture.md
│   ├── demo_walkthrough.md
│   └── security_considerations.md
├── scripts/            # Скрипты верификации
├── tests/              # Модульные тесты 
├── requirements.txt
├── setup.py
└── README.md
```

## API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/certificate/<serial>` | GET | Получение сертификата по серийному номеру |
| `/ca/root` | GET | Корневой CA сертификат |
| `/ca/intermediate` | GET | Промежуточный CA сертификат |
| `/crl?ca=root|intermediate` | GET | CRL |
| `/ocsp` | POST | OCSP запрос (RFC 6960) |
| `/request-cert?template=...` | POST | Выпуск сертификата по CSR |
| `/health` | GET | Проверка состояния |


## Тестирование

```bash
# Все тесты
pytest tests/ -v

# Конкретный модуль
pytest tests/test_ca.py -v
pytest tests/test_audit.py -v

# Performance тест (100 сертификатов)
pytest tests/test_performance.py -v
```

## Документация

| Документ | Описание |
|----------|----------|
| [docs/architecture.md](docs/architecture.md) | Архитектура системы |
| [docs/api_reference.md](docs/api_reference.md) | Полный API Reference |
| [docs/security_considerations.md](docs/security_considerations.md) | Вопросы безопасности |
| [docs/demo_walkthrough.md](docs/demo_walkthrough.md) | Прохождение демо |

## Вопросы безопасности

| Аспект | Реализация |
|--------|------------|
| Шифрование ключей CA | PKCS#8, AES-256-CBC, PBKDF2 |
| Права доступа | 0o600 для ключей, 0o700 для директорий |
| Серийные номера | CSPRNG + timestamp (64-bit) |
| Защита от replay | OCSP nonce |
| Аудит | NDJSON + SHA-256 хеш-цепочка |
| Rate limiting | Token bucket (опционально) |
| End-entity ключи | Незашифрованные (предупреждение) |

## Быстрые команды для справки

```bash
micropki --help
micropki ca --help
micropki ca init --help
micropki ca issue-cert --help
micropki repo serve --help
micropki ocsp serve --help
micropki audit query --help
micropki --version
```

## Демонстрация

Полный демо-сценарий можно запустить одной командой:

```bash
python demo/demo.py
```

Ожидаемый вывод: все шаги с `[PASS]` и итоговое сообщение об успешном завершении.
