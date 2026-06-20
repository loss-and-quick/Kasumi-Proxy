//! Generate the frontend's Zod schemas (`frontend/src/generated/schemas.ts`) from
//! the same `specta::Type` derives that drive the TS bindings — one source, no
//! hand-written validation drift.
//!
//! `specta-zod` emits the `export const …Schema` blocks alphabetically, so a block
//! that refers to a schema declared later hits a `const` temporal-dead-zone error
//! at module load. Our type graph is a DAG (genuine recursion would be `z.lazy`'d,
//! and there is none), so the raw output is topologically sorted here: every schema
//! a block references is declared before it.

use specta_zod::{BigIntExportBehavior, Zod};

/// The committed schema file the frontend imports.
pub const SCHEMAS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../frontend/src/generated/schemas.ts"
);

/// The same wire roots tauri-specta exports to `bindings.ts`; `register` pulls in
/// every transitively-referenced type, so the two files cover one type set.
fn wire_types() -> specta::Types {
    specta::Types::default()
        .register::<kasumi_backend::Command>()
        .register::<kasumi_backend::Response>()
        .register::<kasumi_core::contract::ServiceStatus>()
        .register::<kasumi_core::contract::SubAppliedEvent>()
}

/// Render the topologically-sorted Zod module.
pub fn render() -> String {
    // `PhasesFormat` keeps deserialize-only widening (serde `alias`/`default`/
    // `skip_serializing_if`) faithful by splitting asymmetric types into
    // `_Serialize`/`_Deserialize` schemas, exactly as `bindings.ts` is split.
    let raw = Zod::new()
        .bigint(BigIntExportBehavior::Number)
        .export(&wire_types(), specta_serde::PhasesFormat)
        .expect("zod export");
    topo_sort(&raw)
}

/// Every maximal `…Schema` identifier in `s` (the references a block depends on).
fn schema_idents(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_word(bytes[i]) && (i == 0 || !is_word(bytes[i - 1])) {
            let start = i;
            while i < bytes.len() && is_word(bytes[i]) {
                i += 1;
            }
            let word = &s[start..i];
            if word.ends_with("Schema") {
                out.push(word.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Reorder the generated `export` statements so each schema is declared after the
/// schemas it references. The leading import/comment header is preserved verbatim.
fn topo_sort(src: &str) -> String {
    // Split into the header and the `export …` statements. A statement begins on a
    // line starting at column 0 with `export ` and runs until the next such line
    // (object bodies and the closing `});` are indented or unprefixed).
    let mut header = String::new();
    let mut statements: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    for line in src.lines() {
        if line.starts_with("export ") {
            if started {
                statements.push(std::mem::take(&mut current));
            }
            started = true;
        } else if !started {
            header.push_str(line);
            header.push('\n');
            continue;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        statements.push(current);
    }

    // Pair each `export const NAMESchema = …` with its `export type NAME =
    // z.infer<typeof NAMESchema>` follow-up, keyed by the schema name.
    struct Unit {
        decl: String,
        infer: String,
        order: usize,
    }
    let mut units: std::collections::BTreeMap<String, Unit> = std::collections::BTreeMap::new();
    let mut order = 0usize;
    for stmt in &statements {
        if let Some(rest) = stmt.strip_prefix("export const ") {
            let name = rest.split([' ', '=']).next().unwrap_or("").to_string();
            units
                .entry(name)
                .or_insert(Unit {
                    decl: String::new(),
                    infer: String::new(),
                    order,
                })
                .decl = stmt.clone();
            order += 1;
        } else if stmt.starts_with("export type ") {
            // `… = z.infer<typeof NAMESchema>;` — attach to that schema's unit.
            if let Some(idx) = stmt.find("typeof ") {
                let name: String = stmt[idx + "typeof ".len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if let Some(u) = units.get_mut(&name) {
                    u.infer = stmt.clone();
                }
            }
        }
    }

    // Dependency edges: a unit depends on every other known schema its decl names.
    let known: std::collections::BTreeSet<String> = units.keys().cloned().collect();
    let deps: std::collections::BTreeMap<String, Vec<String>> = units
        .iter()
        .map(|(name, u)| {
            let mut d: Vec<String> = schema_idents(&u.decl)
                .into_iter()
                .filter(|r| r != name && known.contains(r))
                .collect();
            d.sort();
            d.dedup();
            (name.clone(), d)
        })
        .collect();

    // Post-order DFS = dependencies first. Visit roots in the original emission
    // order for a stable, diff-friendly file.
    let mut roots: Vec<&String> = units.keys().collect();
    roots.sort_by_key(|n| units[*n].order);

    let mut emitted: Vec<String> = Vec::new();
    let mut state: std::collections::BTreeMap<&str, u8> = std::collections::BTreeMap::new();
    // Iterative DFS to avoid deep recursion on a large graph.
    for root in roots {
        let mut stack = vec![(root.as_str(), false)];
        while let Some((node, processed)) = stack.pop() {
            match state.get(node) {
                Some(2) => continue,
                Some(1) if !processed => continue, // on the path already (DAG: safe)
                _ => {}
            }
            if processed {
                state.insert(node, 2);
                emitted.push(node.to_string());
                continue;
            }
            state.insert(node, 1);
            stack.push((node, true));
            for dep in &deps[node] {
                if state.get(dep.as_str()).copied() != Some(2) {
                    stack.push((dep.as_str(), false));
                }
            }
        }
    }

    let mut out = header;
    for name in &emitted {
        let u = &units[name];
        out.push_str(&u.decl);
        if !u.infer.is_empty() {
            out.push_str(&u.infer);
        }
        out.push('\n');
    }
    out
}
