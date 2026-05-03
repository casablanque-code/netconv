# netconv

Network config converter. Cisco IOS → Huawei VRP (и другие).

Парсит конфиг, строит vendor-neutral IR, рендерит на целевой вендор.
Каждая конвертация сопровождается репортом: точно / с допущениями / вручную / неизвестно.

## Архитектура

```
crates/
  netconv-core/         # IR типы, трейты, репорт
  netconv-parser-ios/   # Cisco IOS парсер (two-pass)
  netconv-render-vrp/   # Huawei VRP рендерер
  netconv-wasm/         # WASM биндинги для браузера
cli/                    # CLI binary
web/
  index.html            # UI (demo mode без WASM)
  worker.js             # Cloudflare Worker
```

## Быстрый старт

### CLI

```bash
# Сборка
cargo build --release -p netconv

# Конвертация
./target/release/netconv --input router.cfg --from ios --to vrp --output router_vrp.cfg

# С репортом
./target/release/netconv --input router.cfg --warnings

# Полный репорт в JSON
./target/release/netconv --input router.cfg --json
```

### Тесты

```bash
cargo test -p netconv-parser-ios
cargo test -p netconv-core
```

### Веб (demo mode)

Открой `web/index.html` в браузере — работает без сборки WASM.

### Деплой на Cloudflare Workers (полная версия)

```bash
# 1. Собери WASM
cargo install wasm-pack
wasm-pack build crates/netconv-wasm --target bundler --out-dir ../../web/wasm

# 2. Подключи WASM в worker.js (раскомментируй импорт)

# 3. Деплой
npx wrangler deploy
```

## Покрытие: Cisco IOS → Huawei VRP

| Фича               | Статус      | Примечание |
|--------------------|-------------|------------|
| hostname           | ✓ Exact     | → sysname  |
| interface ip       | ✓ Exact     |            |
| shutdown           | ✓ Exact     | → undo shutdown |
| description        | ✓ Exact     |            |
| static routes      | ⚠ Approx   | ip route → ip route-static, AD → preference |
| OSPF process       | ⚠ Approx   | network внутри area, log-peer-change |
| OSPF redistribute  | ⚠ Approx   | redistribute → import-route |
| OSPF passive       | ⚠ Approx   | passive-interface → silent-interface |
| ACL named          | ⚠ Approx   | acl name, rule, traffic-filter |
| ACL numbered       | ⚠ Approx   | нумерация 1-99→2000+, 100-199→3000+ |
| NAT overload (PAT) | ⚠ Approx   | nat outbound на интерфейсе |
| NAT static         | ⚠ Approx   | обратный порядок global/inside |
| HSRP → VRRP        | ⚠ Approx   | несовместимы бинарно, MAC разные |
| HSRP track         | ✗ Manual   | нет прямого аналога, нужен NQA/BFD |
| EIGRP              | ✗ Manual   | проприетарный протокол Cisco |
| BGP                | ⚠ Approx   | neighbor → peer, remote-as → as-number |
| NTP                | ✓ Exact     | ntp-service unicast-server |
| SNMP               | ✓ Exact     | snmp-agent community |
| ip helper-address  | ⚠ Approx   | dhcp relay server-ip + доп. команды |
| switchport access  | ⚠ Approx   | port link-type, port default vlan |
| switchport trunk   | ⚠ Approx   | port trunk allow-pass vlan |

## Добавить новый вендор

1. Создай крейт `crates/netconv-render-eltex/`
2. Реализуй трейт `ConfigRenderer`
3. Добавь в `netconv-wasm/src/lib.rs` новую пару в `match`
4. Добавь опцию в `web/index.html` select#dst-vendor

Парсер IOS трогать не нужно — IR универсальный.

## Лицензия

MIT
