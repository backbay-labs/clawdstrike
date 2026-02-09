use macro_string_eval::eval;

const _: &str = eval!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/nonexist.ent")));

fn main() {}
