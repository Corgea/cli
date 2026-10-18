/// Emit a debug-level diagnostic through the `log` facade.
///
/// Verbosity is controlled centrally by the logger initialized in `main`
/// (`CORGEA_DEBUG=1` or `RUST_LOG=debug`); this is a thin adapter so the many
/// existing `debug(&format!(...))` call sites keep working unchanged.
pub fn debug(input: &str) {
    ::log::debug!("{}", input);
}
