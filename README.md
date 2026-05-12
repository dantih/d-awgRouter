# d-awgRouter

**d-awgRouter** — веб-сервис для управления **AmneziaWG VPN** на macOS: загрузка конфигов, динамический выбор маршрутов из GitHub (RockBlack-VPN/ip-address), управление интерфейсом.

## Как это работает

```
пользователь → веб-интерфейс → Go binary (sudo -n) → awg + route
                  (127.0.0.1:8765)
```

Маршруты (CIDR-подсети) для разных сервисов (Telegram, YouTube, Netflix и т.д.) загружаются из [RockBlack-VPN/ip-address](https://github.com/RockBlack-VPN/ip-address). Выбираешь нужные — они добавляются на AWG-интерфейс.

## Структура папок

```
~/.d-awg-router/
├── configs/telegram.conf     # загруженный WireGuard конфиг
├── cache/<Service>.cidr      # кэшированные CIDR (по файлу на сервис)
├── routes/<Service>          # пустой файл = сервис включён
└── state/current             # состояние (интерфейс, IP)
```

## Быстрый старт

```bash
# 1. Скопировать на Mac и установить
scp bin/d-awg-router-web-darwin-arm64 mac:/tmp/d-awg-router-web
scp install/install.sh mac:/tmp/
ssh mac 'cd /tmp && bash install.sh'

# 2. Открыть в браузере
open http://127.0.0.1:8765/

# 3. Вставить WireGuard конфиг → Save Config
# 4. Выбрать сервисы (Telegram, YouTube, ...) → Save Selection
# 5. Нажать UP
```

## Сборка

Сборка статического бинарника под macOS ARM64 из Linux:

```bash
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o d-awg-router-web cmd/d-awg-router-web/main.go
```

## Требования

- macOS (Apple Silicon)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) установлен
- [awg](https://github.com/amnezia-vpn/amneziawg-tools) в `/usr/local/bin/`
- Одноразовый пароль sudo при установке

## Безопасность

- Сервис слушает только на `127.0.0.1:8765` (локальный доступ)
- Весь доступ к админским командам — через SSH-туннель или локально
- `sudo -n` через строгий `/etc/sudoers.d/d-awg-router` (только разрешённые команды)
- WireGuard приватные ключи хранятся в `~/.d-awg-router/configs/` с правами 0600
