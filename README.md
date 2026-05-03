# netconv

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![WASM](https://img.shields.io/badge/wasm-wasm--bindgen-blue.svg)](https://rustwasm.github.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Конвертер конфигураций сетевого оборудования с репортом конвертации.

Переезжаешь с Cisco на Huawei из-за санкций? Или просто устал от вендор-локина?
Вставляешь конфиг — получаешь готовый конфиг для целевой платформы плюс детальный
репорт: что конвертировано точно, где есть нюансы, что нужно решить вручную.

**Живое демо:** https://netconv.workers.dev *(обнови после деплоя)*

---

## Зачем это нужно

Ручная миграция конфига с Cisco IOS на Huawei VRP — это:
- другой синтаксис для тех же концепций (`ip route` → `ip route-static`, `neighbor` → `peer`)
- разные defaults и поведение (`passive-interface` → `silent-interface`)
- концептуальные несоответствия (`HSRP` → `VRRP` — протоколы несовместимы бинарно)
- риск ошибок при ручном переносе сотен строк

netconv автоматизирует то что можно автоматизировать, и явно помечает то что нельзя.
Слепой конвертер без объяснений опаснее, чем его отсутствие — поэтому каждое
несоответствие сопровождается объяснением и рекомендацией.

---

## Быстрый старт

### Вариант 1 — браузер, без установки

Открой [живое демо](https://netconv.workers.dev), вставь конфиг, нажми **convert** или `Ctrl+Enter`.

Конфиг обрабатывается локально в браузере — на сервер не уходит.

### Вариант 2 — локально с полным WASM парсером

```bash
git clone https://github.com/casablanque-code/netconv.git
cd netconv

# 1. Собери WASM (нужен wasm-pack)
cargo install wasm-pack
wasm-pack build crates/netconv-wasm --target web --out-dir ../../web/wasm

# 2. Запусти HTTP сервер
python3 -m http.server 8080 --directory web/

# 3. Открой в браузере: http://localhost:8080
# Надпись "demo mode" должна исчезнуть — работает реальный Rust парсер
```

> **WSL (Windows):** порты прокидываются автоматически в WSL2.
> Открывай `http://localhost:8080` в браузере Windows — работает напрямую.
> Если не работает: `ip addr show eth0 | grep 'inet '` — используй этот IP.

### Вариант 3 — CLI

```bash
cargo build --release -p netconv

# Конвертация (вывод в stdout)
./target/release/netconv --input router.cfg --from ios --to vrp

# Записать результат в файл
./target/release/netconv --input router.cfg --to vrp --output router_vrp.cfg

# Показать предупреждения и ошибки конвертации
./target/release/netconv --input router.cfg --warnings

# Полный репорт в JSON (для скриптов / CI)
./target/release/netconv --input router.cfg --json > report.json
```

---

## Demo mode vs полный WASM

|                          | Demo mode        | Полный WASM         |
|--------------------------|------------------|---------------------|
| Установка                | не нужна         | `wasm-pack build`   |
| Парсер                   | JS симуляция     | Rust (полный)       |
| Покрытие команд          | ~70%             | всё реализованное   |
| BGP, сложные ACL         | частично         | полностью           |
| address-family, track    | нет              | да                  |
| Конфиг уходит на сервер  | нет              | нет                 |

Demo mode подходит для типовых конфигов (интерфейсы, OSPF, статика, NAT).
Для сложных топологий с BGP, вложенными ACL, HSRP с track — используй WASM.

---

## Покрытие: Cisco IOS → Huawei VRP

| Фича               | Статус    | Примечание |
|--------------------|-----------|------------|
| hostname           | ✓ Exact   | → sysname |
| interface ip       | ✓ Exact   | |
| shutdown / no shut | ✓ Exact   | → undo shutdown |
| description        | ✓ Exact   | |
| NTP server         | ✓ Exact   | → ntp-service unicast-server |
| SNMP community     | ✓ Exact   | → snmp-agent community |
| static routes      | ⚠ Approx | ip route → ip route-static, AD → preference |
| OSPF               | ⚠ Approx | network внутри area, silent-interface, log-peer-change |
| OSPF redistribute  | ⚠ Approx | redistribute → import-route, subnets не нужен |
| BGP neighbors      | ⚠ Approx | neighbor → peer, remote-as → as-number |
| BGP next-hop-self  | ⚠ Approx | → next-hop-local |
| ACL named/numbered | ⚠ Approx | acl name, rule, traffic-filter |
| NAT overload (PAT) | ⚠ Approx | nat outbound на интерфейсе |
| NAT static         | ⚠ Approx | обратный порядок global/inside |
| HSRP → VRRP       | ⚠ Approx | протоколы несовместимы бинарно, MAC разные |
| switchport         | ⚠ Approx | port link-type, port default vlan |
| ip helper-address  | ⚠ Approx | dhcp relay + доп. команды глобально |
| HSRP track         | ✗ Manual | нет прямого аналога → используй NQA/BFD |
| EIGRP              | ✗ Manual | проприетарный протокол Cisco, не поддерживается на VRP |

**Легенда:**
- ✓ **Exact** — точное соответствие, гарантированно корректно
- ⚠ **Approx** — есть аналог с нюансами, репорт объясняет что проверить
- ✗ **Manual** — нет аналога, команда сохраняется как комментарий с объяснением

---

## Архитектура

```
crates/
  netconv-core/        # IR типы, трейты ConfigParser/ConfigRenderer, ConversionReport
  netconv-parser-ios/  # Cisco IOS парсер: pass1 структурное дерево, pass2 семантика
  netconv-render-vrp/  # Huawei VRP рендерер с объяснениями
  netconv-wasm/        # WASM биндинги (wasm-bindgen)
cli/                   # CLI binary (clap)
web/
  index.html           # UI: WASM если собран, demo fallback
  worker.js            # Cloudflare Worker
wrangler.toml          # конфиг деплоя
```

**Добавить новый вендор** = создать крейт + реализовать трейт `ConfigRenderer`.
Парсер и IR не трогаются.

```rust
// Пример: добавить Eltex ESR как цель
impl ConfigRenderer for EltexRenderer {
    fn render(&self, config: &NetworkConfig, report: &mut ConversionReport) -> Result<String, _> {
        // ...
    }
    fn vendor_name(&self) -> &str { "Eltex ESR" }
}
```

---

## Деплой на Cloudflare Workers

```bash
npm install -g wrangler
wrangler login
wrangler deploy
# → https://netconv.YOUR-SUBDOMAIN.workers.dev
```

Конвертация происходит в браузере пользователя (WASM или demo JS).
Workers отдаёт только статику — конфиги на сервер не передаются.

---

## Разработка

```bash
# Проверка компиляции
cargo check

# Тесты
cargo test
cargo test -p netconv-parser-ios  # 7 тестов парсера

# Сборка WASM
wasm-pack build crates/netconv-wasm --target web --out-dir ../../web/wasm

# Локальный сервер
python3 -m http.server 8080 --directory web/
```

---

## Требования

| Компонент | Версия | Зачем |
|-----------|--------|-------|
| Rust      | 1.75+  | всегда |
| wasm-pack | 0.13+  | только для WASM сборки |
| Python 3  | любая  | только для локального HTTP сервера |
| Node.js   | 18+    | только для Cloudflare Workers деплоя |

Установить Rust: https://rustup.rs
Установить wasm-pack: `cargo install wasm-pack`

---

## Лицензия

MIT
