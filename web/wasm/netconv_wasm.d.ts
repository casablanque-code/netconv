/* tslint:disable */
/* eslint-disable */
/**
*/
export function init(): void;
/**
* Основная функция — вызывается из JS
* convert_config(source_config: string, source_vendor: string, target_vendor: string) → JSON string
* @param {string} source_config
* @param {string} source_vendor
* @param {string} target_vendor
* @returns {string}
*/
export function convert_config(source_config: string, source_vendor: string, target_vendor: string): string;
/**
* То же самое, но с профилем устройства ("l2" | "l3" | "").
* Для пары ios->vrp профиль реально фильтрует домен через
* VrpL2Renderer/VrpL3Renderer — VLAN/switchport не попадают в L3-вывод
* и наоборот. Для остальных пар (пока только ios->eltex) профиль ни
* на что не влияет — Eltex ещё не разделён на l2/l3 (см. roadmap),
* используется прежний EltexRenderer.
* @param {string} source_config
* @param {string} source_vendor
* @param {string} target_vendor
* @param {string} profile
* @returns {string}
*/
export function convert_config_profiled(source_config: string, source_vendor: string, target_vendor: string, profile: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly convert_config: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly convert_config_profiled: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly init: () => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
