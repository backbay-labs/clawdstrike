use macro_string_eval::eval;

const _: &str = eval!(concat!("ru"i32, "st"));

const _: &str = eval!(concat!(' 'i32));

const _: &str = eval!(concat!(1i256));

const _: &str = eval!(concat!(1.0f256));

fn main() {}
