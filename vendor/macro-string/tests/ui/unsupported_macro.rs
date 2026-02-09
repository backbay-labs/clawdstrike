use macro_string_eval::eval;

const _: &str = eval!(include_bytes!("..."));

fn main() {}
