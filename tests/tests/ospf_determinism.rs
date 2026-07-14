//! Регрессия (баг #5 из ревью): OSPF areas собирались в HashMap, чей
//! итерационный порядок не гарантирован между запусками — порядок
//! area-блоков в выводе мог отличаться от запуска к запуску на одном и том
//! же входе, создавая ложные diff'ы при сравнении/CI.
//!
//! Эти тесты проверяют, что (а) порядок areas в IR соответствует порядку
//! первого упоминания area в исходном конфиге, и (б) повторный парсинг
//! одного и того же конфига даёт идентичный результат.

use netconv_core::traits::ConfigParser;
use netconv_parser_ios::IosParser;

const MULTI_AREA_OSPF_CONFIG: &str = r#"
hostname CORE-RTR
!
router ospf 1
 router-id 1.1.1.1
 network 10.3.0.0 0.0.0.255 area 3
 network 10.1.0.0 0.0.0.255 area 1
 network 10.0.0.0 0.0.0.255 area 0
 network 10.2.0.0 0.0.0.255 area 2
 area 2 stub
 area 1 nssa
"#;

#[test]
fn ospf_areas_preserve_first_mention_order() {
    let parser = IosParser;
    let (cfg, _) = parser.parse(MULTI_AREA_OSPF_CONFIG).unwrap();
    let ospf = &cfg.routing.ospf[0];

    // Порядок первого упоминания в конфиге: area 3, area 1, area 0, area 2.
    let area_order: Vec<String> = ospf.areas.iter().map(|a| format!("{:?}", a.area)).collect();

    assert_eq!(
        area_order,
        vec![
            "Normal(3)".to_string(),
            "Normal(1)".to_string(),
            "Backbone".to_string(),
            "Normal(2)".to_string(),
        ],
        "areas must preserve the order in which they were first mentioned in the source config, got {:?}",
        area_order
    );
}

#[test]
fn ospf_areas_order_is_stable_across_repeated_parses() {
    // Многократный парсинг одного и того же входа должен давать
    // идентичный порядок — это бы ловило недетерминизм HashMap, если бы
    // он снова появился (HashMap порядок может различаться между запусками
    // процесса из-за случайного seed хэш-функции).
    let parser = IosParser;
    let mut orders = Vec::new();

    for _ in 0..20 {
        let (cfg, _) = parser.parse(MULTI_AREA_OSPF_CONFIG).unwrap();
        let order: Vec<String> = cfg.routing.ospf[0]
            .areas
            .iter()
            .map(|a| format!("{:?}", a.area))
            .collect();
        orders.push(order);
    }

    let first = &orders[0];
    for (i, order) in orders.iter().enumerate() {
        assert_eq!(
            order, first,
            "parse #{} produced a different area order than parse #0",
            i
        );
    }
}
