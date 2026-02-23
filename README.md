# MicroPKI

Минимальная реализация инфраструктуры открытых ключей (PKI) для образовательных целей.

## Описание

MicroPKI — это легковесный инструмент для создания и управления самоподписанным корневым удостоверяющим центром (Root Certificate Authority). Проект обеспечивает безопасную генерацию ключей, создание X.509 сертификатов и аудит логирования.

## Возможности (Спринт 1)

- Генерация самоподписанных корневых сертификатов CA
- Поддержка ключей RSA-4096 и ECC P-384
- Безопасное хранение зашифрованных закрытых ключей (PKCS#8 с AES-256)
- X.509 v3 сертификаты с правильными расширениями
- Комплексное аудит-логирование
- Policy document
- Совместимость с OpenSSL

## Установка

### Требования

- Python 3.8 или выше
- pip

### Настройка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/ksesha-kr/micropki.git
cd micropki
```

2. Создайте виртуальное окружение:
```bash
python3 -m venv venv
source venv/bin/activate
```
На Windows:
```
venv\Scripts\activate
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

4. Установите пакет:
```bash
pip install -e .
```

## Использование

### Инициализация корневого CA с RSA

```bash
mkdir -p secrets
echo "моя-надежная-парольная-фраза" > ./secrets/ca.pass

micropki ca init \
    --subject "/CN=Демо Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 3650 \
    --log-file ./logs/ca-init.log
```

### Инициализация корневого CA с ECC

```bash
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki
```

### Параметры командной строки

| Параметр | Описание | Обязательный |
|----------|----------|--------------|
| `--subject` | Distinguished Name (например, `/CN=Мой CA` или `CN=Мой CA,O=Демо`) | Да |
| `--key-type` | Тип ключа: `rsa` или `ecc` (по умолчанию: `rsa`) | Нет |
| `--key-size` | Размер ключа в битах: 4096 для RSA, 384 для ECC (по умолчанию: 4096) | Нет |
| `--passphrase-file` | Путь к файлу с парольной фразой | Да |
| `--out-dir` | Выходная директория (по умолчанию: `./pki`) | Нет |
| `--validity-days` | Срок действия в днях (по умолчанию: 3650 ≈ 10 лет) | Нет |
| `--log-file` | Путь к файлу лога (по умолчанию: stderr) | Нет |
| `--force` | Перезаписывать существующие файлы без подтверждения | Нет |

## Структура проекта

```
micropki/
├── micropki/           # Основной пакет
│   ├── __init__.py
│   ├── __main__.py    # Точка входа
│   ├── cli.py         # Интерфейс командной строки
│   ├── ca.py          # Операции с корневым CA
│   ├── certificates.py # Работа с X.509 сертификатами
│   ├── crypto_utils.py # Криптографические утилиты
│   └── logger.py      # Настройка логирования
├── tests/             # Модульные тесты
│   ├── __init__.py
│   ├── test_ca.py
│   ├── test_certificates.py
│   └── test_crypto_utils.py
├── scripts/           # Скрипты для верификации
│   ├── test_key_match.py
│   ├── test_encrypted_key_load.py
│   └── verify_with_openssl.sh
├── setup.py           # Файл установки пакета
├── requirements.txt   # Зависимости Python
├── README.md         # Этот файл
└── .gitignore        # Правила для Git
```

## Тестирование

### Запуск модульных тестов

```bash
pip install pytest pytest-cov

pytest tests/ -v

pytest tests/ --cov=micropki --cov-report=term-missing

pytest tests/test_ca.py::test_ca_initialization_rsa -v
```

### Ручная верификация

1. **Проверка сертификата с OpenSSL**:
```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout

openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

2. **Проверка соответствия ключа и сертификата**:
```bash
python scripts/test_key_match.py \
    --key pki/private/ca.key.pem \
    --cert pki/certs/ca.cert.pem \
    --passphrase-file secrets/ca.pass
```

3. **Проверка загрузки зашифрованного ключа**:
```bash
python scripts/test_encrypted_key_load.py \
    --key pki/private/ca.key.pem \
    --passphrase-file secrets/ca.pass
```

4. **Тест совместимости с OpenSSL**:
```bash
chmod +x scripts/verify_with_openssl.sh

./scripts/verify_with_openssl.sh pki/certs/ca.cert.pem
```

### Негативные тестовые сценарии

Проверьте обработку ошибок:
1. Отсутствует subject
```bash
micropki ca init --passphrase-file secrets/ca.pass
```
2. Неверный синтаксис DN
```
micropki ca init --subject "Неверный DN" --passphrase-file secrets/ca.pass
```
3. ECC с неправильным размером ключа
```
micropki ca init \
    --subject "/CN=Тест" \
    --key-type ecc \
    --key-size 256 \
    --passphrase-file secrets/ca.pass
```    

4. Несуществующий файл с парольной фразой
```
micropki ca init \
    --subject "/CN=Тест" \
    --passphrase-file /несуществующий/файл
```

 5. Директория без прав на запись
```
micropki ca init \
    --subject "/CN=Тест" \
    --passphrase-file secrets/ca.pass \
    --out-dir /root/pki
```

## Зависимости

```
cryptography>=3.0     
pytest>=6.0         
pytest-cov>=2.0        
```

Установка зависимостей:
```bash
pip install -r requirements.txt
```

## Пример рабочего процесса
1. Очистка предыдущих результатов
```bash
rm -rf pki logs secrets
mkdir -p secrets logs
```
2. Создание парольной фразы
```
echo "НадежнаяПарольнаяФраза123!@#" > secrets/ca.pass
chmod 600 secrets/ca.pass
```
3. Создание корневого CA
```
micropki ca init \
    --subject "/CN=Production Root CA/O=Моя Компания/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 7300 \
    --log-file ./logs/init.log
```
4. Проверка результатов
```
echo -e "\n=== Информация о сертификате ==="
openssl x509 -in pki/certs/ca.cert.pem -subject -issuer -dates -noout

echo -e "\n=== Верификация ==="
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem

echo -e "\n=== Соответствие ключа ==="
python scripts/test_key_match.py \
    --key pki/private/ca.key.pem \
    --cert pki/certs/ca.cert.pem \
    --passphrase-file secrets/ca.pass

echo -e "\n=== Содержимое лога ==="
cat logs/init.log
```

## Вопросы безопасности

- **Шифрование закрытых ключей**: Ключи шифруются с использованием PKCS#8 с AES-256-CBC и PBKDF2
- **Права доступа к файлам**: Файлы ключей хранятся со строгими правами доступа (0o600 на Unix-системах)
- **Обработка парольных фраз**: Парольные фразы никогда не логируются, не отображаются и не выводятся на экран
- **Криптографические библиотеки**: Все операции используют проверенную библиотеку `cryptography`
- **Случайные числа**: Серийные номера сертификатов генерируются с использованием CSPRNG (модуль `secrets`)

## Быстрые команды для справки

```bash
micropki --help

micropki ca --help

micropki ca init --help

micropki --version
```