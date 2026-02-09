#[rustversion::attr(not(nightly), ignore = "requires nightly")]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
