# FeOxDB 0.6.0 local patch

Source: https://static.crates.io/crates/feoxdb/feoxdb-0.6.0.crate
SHA-256: `a4ee5da098f0cf104db94054bbc469b043b5dd5870473e1321d6288016fd8775`.

The upstream library source, license and notice are retained. Unused external
example, test and benchmark targets are omitted from the package manifest.
`src/constants.rs` caps the default memory limit at `usize::MAX` on 32-bit
targets, avoiding the upstream `4 * GB` constant overflow. dhxpro supplies its
own configured memory limit.
