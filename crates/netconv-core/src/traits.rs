use crate::ir::NetworkConfig;
use crate::profile::{detect_domain_mismatches, DeviceProfile};
use crate::report::ConversionReport;

/// Парсер: текст конфига → IR + частичный репорт (что не распознано)
pub trait ConfigParser {
    type Error: std::fmt::Debug;

    fn parse(&self, input: &str) -> Result<(NetworkConfig, ConversionReport), Self::Error>;

    fn vendor_name(&self) -> &str;
}

/// Рендерер: IR → текст конфига целевого вендора + дополняет репорт
pub trait ConfigRenderer {
    type Error: std::fmt::Debug;

    fn render(
        &self,
        config: &NetworkConfig,
        report: &mut ConversionReport,
    ) -> Result<String, Self::Error>;

    fn vendor_name(&self) -> &str;
}

/// Полный пайплайн: парсер + рендерер → одна функция конвертации
pub fn convert<P, R>(
    parser: &P,
    renderer: &R,
    input: &str,
) -> Result<ConversionOutput, ConvertError>
where
    P: ConfigParser,
    R: ConfigRenderer,
{
    let (ir, mut report) = parser.parse(input)
        .map_err(|e| ConvertError::ParseError(format!("{:?}", e)))?;

    let output = renderer.render(&ir, &mut report)
        .map_err(|e| ConvertError::RenderError(format!("{:?}", e)))?;

    Ok(ConversionOutput { config_text: output, report })
}

/// Тот же пайплайн что и `convert`, но дополнительно сверяет разобранный
/// IR с выбранным профилем устройства (L2/L3) и кладёт найденные
/// несоответствия домена в `report.domain_mismatches` — до того как
/// рендерер успеет молча отрисовать или тихо отбросить чужой домен.
///
/// Рендерер на этом этапе ещё не фильтрует IR по профилю — это следующий
/// шаг (разделение render-крейтов на l2/l3). Здесь только диагностика.
pub fn convert_with_profile<P, R>(
    parser: &P,
    renderer: &R,
    input: &str,
    profile: DeviceProfile,
) -> Result<ConversionOutput, ConvertError>
where
    P: ConfigParser,
    R: ConfigRenderer,
{
    let (ir, mut report) = parser.parse(input)
        .map_err(|e| ConvertError::ParseError(format!("{:?}", e)))?;

    report.domain_mismatches = detect_domain_mismatches(&ir, profile);

    let output = renderer.render(&ir, &mut report)
        .map_err(|e| ConvertError::RenderError(format!("{:?}", e)))?;

    Ok(ConversionOutput { config_text: output, report })
}

#[derive(Debug)]
pub struct ConversionOutput {
    pub config_text: String,
    pub report: ConversionReport,
}

#[derive(Debug)]
pub enum ConvertError {
    ParseError(String),
    RenderError(String),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::ParseError(e)  => write!(f, "Parse error: {}", e),
            ConvertError::RenderError(e) => write!(f, "Render error: {}", e),
        }
    }
}
