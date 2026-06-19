//! `cargo run -p kasumi-desktop --bin codegen` — regenerate the frontend's
//! generated files (`frontend/src/generated/{bindings,schemas,defaults}.ts`)
//! from the Rust types. The cargo-native equivalent of an npm codegen script;
//! the same `export_generated` the debug build and the drift test run.

fn main() {
    kasumi_desktop_lib::export_generated();
    println!("regenerated frontend/src/generated/{{bindings,schemas,defaults}}.ts");
}
