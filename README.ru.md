# d-awgRouter

🌐 **[English](README.md)** | **Русский** ↓

 — веб-сервис для управления **WireGuard / AmneziaWG VPN** на macOS: загрузка конфигов, динамический выбор маршрутов из GitHub (RockBlack-VPN/ip-address), управление интерфейсом.

Автоматически определяет тип конфига — обычный WireGuard или AmneziaWG — по наличию параметров `Jc`/`Jmin`/`Jmax` в конфиге.

Поддерживает несколько конфигураций, мультиязычный интерфейс (EN / RU), понятный веб-интерфейс.

## Как это работает

```
пользователь → веб-интерфейс (127.0.0.1:8765) → Go binary (sudo -n)
                                              ├── AmneziaWG: awg + amneziawg-go
                                              └── WireGuard: wg + wireguard-go
```

Маршруты (CIDR-подсети) для разных сервисов (Telegram, YouTube, Netflix и т.д.) загружаются из [RockBlack-VPN/ip-address](https://github.com/RockBlack-VPN/ip-address). Выбираешь нужные — они добавляются на VPN-интерфейс.

## Структура папок

```
~/.d-awg-router/
├── configs/*.conf            # все загруженные WireGuard/AWG конфиги
├── active                    # имя активного конфига
├── cache/<Service>.cidr      # кэшированные CIDR (по файлу на сервис)
├── routes/<Service>          # пустой файл = сервис включён
├── state/current             # состояние (интерфейс, IP)
├── lang                      # выбранный язык (en / ru)
└── awg-icon.png              # иконка сервиса
```

## Быстрый старт

### Установка из release

```bash
# Скачать последнюю версию
curl -sfL -o /tmp/d-awg-router-web https://github.com/dantih/d-awgRouter/releases/latest/download/d-awg-router-web-darwin-arm64
chmod +x /tmp/d-awg-router-web
echo "YOUR_PASSWORD" | sudo -S mv /tmp/d-awg-router-web /usr/local/bin/d-awg-router-web
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
        <string>/usr/local/bin/d-awg-router-web</string>
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

### Использование

```bash
# Открыть в браузере (через SSH-туннель)
ssh -L 8765:127.0.0.1:8765 mac

# В браузере:
# 1. Config → вставить WireGuard или AmneziaWG конфиг → Save
# 2. Config → Activate (чтобы сделать активным)
# 3. Services → выбрать нужные (Telegram, YouTube, ...) → Save Selection
# 4. Control → UP
```

## Веб-интерфейс

Три вкладки:

| Вкладка | Назначение |
|---------|------------|
| **Control** | ВКЛ / ВЫКЛ / Перезапуск VPN, просмотр статуса и маршрутов |
| **Services** | Выбор CIDR-сервисов для роутинга через VPN |
| **Config** | Список конфигураций, редактор, создание/удаление/активация |

В хедере — переключатель языка (English / Русский).

## Требования

### Для AmneziaWG
- macOS (Apple Silicon)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) бинарник
- [awg](https://github.com/amnezia-vpn/amneziawg-tools) (amneziawg-tools)

### Для обычного WireGuard
- [wireguard-go](https://www.wireguard.com/) — `brew install wireguard-go`
- [wireguard-tools](https://www.wireguard.com/) — `brew install wireguard-tools`

Бинарники `wg` и `wireguard-go` должны быть в PATH (или в `/opt/homebrew/bin/`).

### sudoers

После установки добавьте в `/etc/sudoers.d/d-awg-router`:

```
YOUR_USER ALL=(ALL) NOPASSWD: /usr/local/bin/d-awg-router-web, /usr/local/bin/awg, /usr/local/bin/amneziawg-go, /sbin/route, /sbin/ifconfig, /bin/kill, /bin/rm, /bin/pgrep, /opt/homebrew/bin/wg, /opt/homebrew/bin/wireguard-go
```

Либо воспользуйтесь [install.sh](install.sh) — он создаёт sudoers автоматически.

## Сборка

```bash
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o d-awg-router-web-darwin-arm64 ./cmd/d-awg-router-web/
```

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
    "btn.down": "BAISSER",
    // ...
},
```
2. Обнови селектор в HTML (добавь `<option value="fr">Français</option>`)
3. Пересобери

IP-адреса, имена интерфейсов и сырые конфиги — всегда на английском.

## Безопасность

- Сервис слушает только на `127.0.0.1:8765` (локальный доступ)
- Весь доступ к админским командам — через SSH-туннель или локально
- `sudo -n` через строгий `/etc/sudoers.d/d-awg-router` (только разрешённые команды)
- WireGuard приватные ключи хранятся в `~/.d-awg-router/configs/` с правами 0600
- Конфиги VPN не хранятся в git-истории
