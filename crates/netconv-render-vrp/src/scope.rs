/// Внутренний scope рендеринга для этого крейта. Не путать с
/// `netconv_core::profile::DeviceProfile` — та ось выбирается
/// пользователем на входе всей конвертации (см. netconv-core::profile);
/// здесь это то, что конкретно умеет фильтровать рендерер VRP.
///
/// `All` сохраняет прежнее поведение `VrpRenderer` (полный дамп IR,
/// без разбора домена) — оставлено ради обратной совместимости с
/// вызовами `--to vrp` без `--profile` и со старыми интеграционными
/// тестами. Новый код должен использовать `VrpL2Renderer` / `VrpL3Renderer`
/// (scope L2 / L3), которые и есть цель этого рефакторинга.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderScope {
    L2,
    L3,
    All,
}

impl RenderScope {
    pub(crate) fn wants_l2(&self) -> bool {
        matches!(self, RenderScope::L2 | RenderScope::All)
    }

    pub(crate) fn wants_l3(&self) -> bool {
        matches!(self, RenderScope::L3 | RenderScope::All)
    }
}
