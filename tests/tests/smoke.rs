//! Smoke-тесты: обе поддерживаемые пары конвертации (ios->vrp, ios->eltex)
//! не должны падать на простом, валидном конфиге.
//!
//! Регрессия (баг #7 из ревью): CLI не знал о паре ios->eltex, хотя
//! EltexRenderer уже существовал и использовался в wasm-биндинге — теперь
//! CLI (cli/src/main.rs) тоже эту пару поддерживает. Этот тест не запускает
//! сам бинарник CLI (нет смысла дублировать clap-парсинг аргументов в тестах),
//! а проверяет ту же самую точку входа (`convert()`), которую CLI вызывает
//! для обеих пар.

use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_eltex::EltexRenderer;
use netconv_render_vrp::VrpRenderer;

const MINIMAL_CONFIG: &str = r#"
hostname SMOKE-TEST-RTR
!
interface GigabitEthernet0/0
 description WAN
 ip address 203.0.113.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
"#;

#[test]
fn ios_to_vrp_smoke_test() {
    let output = convert(&IosParser, &VrpRenderer, MINIMAL_CONFIG)
        .expect("ios -> vrp conversion should not fail on a minimal valid config");
    assert!(!output.config_text.is_empty());
    assert!(output.config_text.contains("SMOKE-TEST-RTR"));
}

#[test]
fn ios_to_eltex_smoke_test() {
    let output = convert(&IosParser, &EltexRenderer, MINIMAL_CONFIG)
        .expect("ios -> eltex conversion should not fail on a minimal valid config");
    assert!(!output.config_text.is_empty());
    assert!(output.config_text.contains("SMOKE-TEST-RTR"));
}
