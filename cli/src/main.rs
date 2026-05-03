use clap::Parser;
use netconv_core::traits::convert;
use netconv_core::report::Severity;
use netconv_parser_ios::IosParser;
use netconv_render_vrp::VrpRenderer;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "netconv")]
#[command(about = "Network config converter — Cisco IOS → Huawei VRP (and more)")]
#[command(version = "0.1.0")]
struct Args {
    /// Путь к исходному конфигу
    #[arg(short, long)]
    input: PathBuf,

    /// Путь для записи конвертированного конфига
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Исходный вендор: ios, vrp
    #[arg(long, default_value = "ios")]
    from: String,

    /// Целевой вендор: vrp, eltex (скоро)
    #[arg(long, default_value = "vrp")]
    to: String,

    /// Показать полный репорт конвертации
    #[arg(long, default_value_t = false)]
    report: bool,

    /// Показать только warnings и errors
    #[arg(long, default_value_t = false)]
    warnings: bool,

    /// Вывести репорт в JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

fn main() {
    let args = Args::parse();

    // Читаем исходный конфиг
    let input = match std::fs::read_to_string(&args.input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Ошибка чтения файла {:?}: {}", args.input, e);
            std::process::exit(1);
        }
    };

    // Конвертируем
    let result = match (args.from.as_str(), args.to.as_str()) {
        ("ios", "vrp") => {
            convert(&IosParser, &VrpRenderer, &input)
        }
        (src, tgt) => {
            eprintln!("Пара {}->{} пока не поддерживается.", src, tgt);
            eprintln!("Доступно: --from ios --to vrp");
            std::process::exit(1);
        }
    };

    let output = match result {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Ошибка конвертации: {}", e);
            std::process::exit(1);
        }
    };

    // Выводим конфиг
    match &args.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &output.config_text) {
                eprintln!("Ошибка записи файла {:?}: {}", path, e);
                std::process::exit(1);
            }
            println!("✓ Конфиг записан в {:?}", path);
        }
        None => {
            println!("{}", output.config_text);
        }
    }

    // Summary всегда
    let r = &output.report;
    eprintln!("\n─────────────────────────────────────────");
    eprintln!(" netconv: {} → {}", r.source_vendor, r.target_vendor);
    eprintln!("─────────────────────────────────────────");
    eprintln!(" Всего команд:           {}", r.summary.total_commands);
    eprintln!(" ✓ Точно:                {} ({:.0}%)", r.summary.exact, r.summary.exact_pct());
    eprintln!(" ⚠ С допущениями:        {}", r.summary.approximate);
    eprintln!(" ✗ Требует решения:      {}", r.summary.manual_required);
    eprintln!(" ? Нераспознано:         {}", r.summary.unknown);
    eprintln!(" Coverage:               {:.0}%", r.summary.coverage_pct());
    eprintln!("─────────────────────────────────────────");

    if args.json {
        // Сериализуем репорт в JSON
        let items: Vec<serde_json::Value> = r.items.iter().map(|item| {
            serde_json::json!({
                "severity": format!("{:?}", item.severity),
                "category": item.category,
                "source": item.source_snippet,
                "target": item.target_snippet,
                "message": item.message,
                "recommendation": item.recommendation,
            })
        }).collect();

        let json = serde_json::json!({
            "summary": {
                "total": r.summary.total_commands,
                "exact": r.summary.exact,
                "approximate": r.summary.approximate,
                "manual": r.summary.manual_required,
                "unknown": r.summary.unknown,
                "coverage_pct": r.summary.coverage_pct(),
            },
            "items": items,
        });
        eprintln!("{}", serde_json::to_string_pretty(&json).unwrap());
        return;
    }

    // Текстовый репорт
    if args.warnings || args.report {
        let items: Vec<_> = if args.report {
            r.items.iter().collect()
        } else {
            r.warnings_and_errors()
        };

        if items.is_empty() {
            eprintln!(" Нет предупреждений.");
        } else {
            eprintln!();
            for item in items {
                let icon = match item.severity {
                    Severity::Ok    => "✓",
                    Severity::Warn  => "⚠",
                    Severity::Error => "✗",
                    Severity::Info  => "?",
                };
                eprintln!("{} [{}] {}", icon, item.category, item.message);
                eprintln!("  Было: {}", item.source_snippet);
                if let Some(t) = &item.target_snippet {
                    eprintln!("  Стало: {}", t);
                }
                if let Some(rec) = &item.recommendation {
                    eprintln!("  → {}", rec);
                }
                eprintln!();
            }
        }
    } else {
        if r.summary.manual_required > 0 {
            eprintln!("\n⚠ {} команд требуют ручного решения. Запусти с --warnings для деталей.", r.summary.manual_required);
        }
        if r.summary.unknown > 0 {
            eprintln!("? {} нераспознанных команд сохранены как комментарии.", r.summary.unknown);
        }
    }
}
