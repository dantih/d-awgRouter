# d-awgRouter

🌐 **[English](README.md)** | **Русский** ↓

 — веб-сервис для управления **WireGuard / AmneziaWG VPN** на macOS:
загрузка конфигов, динамический выбор маршрутов из GitHub (RockBlack-VPN/ip-address),
управление интерфейсом (UP/DOWN) и **Full Tunnel** (весь трафик через VPN
с регистрацией в System Configuration через scutil).

Автоматически определяет тип конфига — обычный WireGuard или AmneziaWG —
по наличию параметров `Jc`/`Jmin`/`Jmax`.

Поддерживает несколько конфигураций, мультиязычный интерфейс (EN / RU),
debug-режим, автонастройку sudoers.

## Как это работает

```
пользователь → веб-интерфейс (127.0.0.1:8765) → Go binary (sudo -n)
                                              ├── AmneziaWG: awg + amneziawg-go
                                              └── WireGuard: wg + wireguard-go
```

Маршруты (CIDR-подсети) для разных сервисов (Telegram, YouTube, Netflix и т.д.)
загружаются из [RockBlack-VPN/ip-address](https://github.com/RockBlack-VPN/ip-address).
Выбираешь нужные — они добавляются на VPN-интерфейс.

## Возможности

- **Split tunneling** — роутинг через VPN только выбранных сервисов
- **Full Tunnel** — весь трафик через VPN (через scutil System Configuration)
- **Множество конфигов** — сохраняй, переключай, редактируй
- **Автоопределение** — определяет WireGuard или AmneziaWG по параметрам конфига
- **Debug-режим** — детальное логирование в `/tmp/com.d-awg-router.web.log`
- **Веб-интерфейс** — вкладки Control / Services / Config
- **Мультиязычность** — английский и русский встроены
- **Управление сервисом** — интеграция с launchd, CLI `start`/`stop`/`restart`/`status`

## Структура папок

```
~/.d-awg-router/
├── configs/*.conf        # WireGuard/AWG конфиги (управление через веб)
├── active                # имя активного конфига
├── cache/<Service>.cidr  # кэшированные CIDR (по файлу на сервис)
├── routes/<Service>      # пустой файл = сервис включён
├── state/
│   ├── current           # текущий интерфейс и IP
│   ├── ft_exclude        # exclude-маршруты для Full Tunnel (по CIDR на строку)
│   ├── ft_service_uuid   # UUID scutil-сервиса для Full Tunnel
│   ├── full_tunnel       # "true" если Full Tunnel включён
│   ├── orig_default_gw   # оригинальный default gateway (для exclude-маршрутов)
│   ├── wg_pid            # PID процесса wireguard-go/amneziawg-go
│   └── debug             # существует = debug режим (touch для включения)
├── lang                  # выбранный язык (en / ru)
└── awg-icon.png          # иконка сервиса
```

## Быстрый старт

### Установка бинарника

```bash
# Последний релиз
curl -sfL -o /tmp/d-awg-router-web https://github.com/dantih/d-awgRouter/releases/latest/download/d-awg-router-web-darwin-arm64
chmod +x /tmp/d-awg-router-web
mkdir -p ~/.d-awg-router
mv /tmp/d-awg-router-web ~/.d-awg-router/d-awg-router-web
```

### Или через install.sh

```bash
curl -sfL https://raw.githubusercontent.com/dantih/d-awgRouter/main/install.sh | bash
```

### Настройка launchd

```bash
mkdir -p ~/Library/LaunchAgents

cat > ~/Library/LaunchAgents/com.d-awg-router.web.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.d-awg-router.web</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/$(whoami)/.d-awg-router/d-awg-router-web</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Users/$(whoami)</string>
    <key>StandardOutPath</key>
    <string>/tmp/com.d-awg-router.web.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/com.d-awg-router.web.err</string>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.d-awg-router.web.plist
```

### sudoers

`install.sh` создаёт sudoers автоматически. Если вручную:

```
# /etc/sudoers.d/d-awg-router
YOUR_USER ALL=(ALL) NOPASSWD: /Users/YOUR_USER/.d-awg-router/d-awg-router-web, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /opt/homebrew/bin/wg, /opt/homebrew/bin/wireguard-go, /usr/sbin/scutil
```

## CLI-команды

```bash
# Управление веб-сервисом через launchd
~/.d-awg-router/d-awg-router-web start
~/.d-awg-router/d-awg-router-web stop
~/.d-awg-router/d-awg-router-web restart

# Статус сервиса (PID, VPN интерфейс, конфиг, маршруты)
~/.d-awg-router/d-awg-router-web status

# Включение/выключение debug-режима (создаёт/удаляет state/debug)
~/.d-awg-router/d-awg-router-web debug on
~/.d-awg-router/d-awg-router-web debug off

# Ручное уничтожение utun-интерфейса (⚠️ осторожно)
~/.d-awg-router/d-awg-router-web destroy utun7
```

## Использование

```bash
# Открыть веб-интерфейс (через SSH-туннель)
ssh -L 8765:127.0.0.1:8765 mac
# Потом открыть http://127.0.0.1:8765
```

### Шаги

1. **Config** → вставить WireGuard или AmneziaWG конфиг → Save
2. **Config** → нажать Activate на нужном конфиге
3. **Services** → выбрать нужные сервисы (Telegram, YouTube, ...) → Save Selection
4. **Control** → UP

## Режим Full Tunnel

> Направляет **весь** трафик через VPN-интерфейс, используя System Configuration (scutil).

### Как работает

1. При включении чекбокса **Full Tunnel** на вкладке Control вызывается `reloadFTEnabled()`
2. В System Configuration через `scutil` регистрируется новый Network Service
3. Сервис помечается как Primary с наивысшим приоритетом
4. **Исключающие маршруты** (exclude routes) добавляются для:
   - Оригинальной (не-VPN) подсети — чтобы сохранить доступ к локальной сети
   - Endpoint-адреса VPN — чтобы само VPN-соединение не разорвалось
   - Подсети SSH-клиента (если определяется — чтобы не потерять SSH-доступ)
   - Link-local `169.254.0.0/16`
5. Исключения сохраняются в `state/ft_exclude` для очистки при выключении
6. При выключении сервис удаляется из scutil и exclude-маршруты удаляются

### Когда активируется

- **При UP** — если Full Tunnel был ранее включён (в файле `state/full_tunnel`),
  `reloadFTEnabled()` вызывается автоматически после поднятия интерфейса
- **По тогглу** — переключение чекбокса Full Tunnel в UI сразу регистрирует
  или убирает сервис в System Configuration

### Автовключение при старте

Если `state/full_tunnel = true` до нажатия UP, Full Tunnel применяется
автоматически после поднятия интерфейса. Ничего дополнительно нажимать не нужно.

## Веб-интерфейс

Четыре вкладки:

| Вкладка | Назначение |
|---------|------------|
| **Control** | UP / DOWN / Перезапуск VPN, переключатель Full Tunnel, статус и маршруты |
| **Services** | Выбор CIDR-сервисов для роутинга через VPN, кнопка Force Routes |
| **Config** | Список конфигов, просмотр/редактирование, создание, удаление, активация |
| **About** | Версия, что нового, информация о сборке |

В хедере — переключатель языка (English / Русский).

## Debug-режим

Включает детальное логирование в `/tmp/com.d-awg-router.web.log`:

```bash
# Через CLI
~/.d-awg-router/d-awg-router-web debug on
# Потом перезапустить: ~/.d-awg-router/d-awg-router-web restart

# Или вручную
touch ~/.d-awg-router/state/debug
# Потом перезапустить сервис

# Смотреть логи в реальном времени
tail -f /tmp/com.d-awg-router.web.log
```

В debug-режиме каждая операция пишет шаги: определение интерфейса,
управление PID, регистрация scutil, маршрутные команды.

## Требования

### Для AmneziaWG
- macOS (Apple Silicon)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) бинарник
- [awg](https://github.com/amnezia-vpn/amneziawg-tools) (amneziawg-tools)

### Для обычного WireGuard
- `brew install wireguard-go`
- `brew install wireguard-tools`

Бинарники должны быть в PATH или в `/opt/homebrew/bin/`.

## Автоопределение типа VPN

Система автоматически определяет тип конфига:

| Флаг | AmneziaWG | WireGuard |
|------|-----------|-----------|
| `Jc` | ✅ есть | ❌ нет |
| `Jmin` | ✅ есть | ❌ нет |
| `Jmax` | ✅ есть | ❌ нет |
| Бекенд | `amneziawg-go` | `wireguard-go` |
| Инструменты | `awg` | `wg` |

## Мультиязычность

Языковые строки вынесены в `cmd/d-awg-router-web/lang.go`. Чтобы добавить новый язык:

1. Добавь блок в `langData`:
```go
"fr": LangMap{
    "btn.up": "MONTER",
    // ...
},
```
2. Обнови селектор в HTML (добавь `<option value="fr">Français</option>`)
3. Пересобери

IP-адреса, имена интерфейсов и сырые конфиги — всегда на английском.

## Сборка

```bash
# Из исходников
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o d-awg-router-web ./cmd/d-awg-router-web/

# Для разработки (с debug-символами)
GOOS=darwin GOARCH=arm64 go build -o d-awg-router-web ./cmd/d-awg-router-web/
```

## Безопасность

- Сервис слушает только на `127.0.0.1:8765` (локальный доступ)
- Весь доступ к админским командам — через SSH-туннель или локально
- `sudo -n` через строгий `/etc/sudoers.d/d-awg-router` (только разрешённые команды)
- WireGuard приватные ключи хранятся в `~/.d-awg-router/configs/` с правами 0600
- Конфиги VPN не хранятся в git-истории
