use macro_string_eval::eval;

const _: &str = eval!(include_str!("relative/path.rs"));

fn main() {}
