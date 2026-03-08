use std::io;

#[track_caller]
pub fn expect_ok(result: io::Result<()>) {
    assert!(
        result.is_ok(),
        "result = {}, should be OK()",
        result.as_ref().unwrap_err(),
    );
}

#[track_caller]
pub fn expect_err(result: io::Result<()>, kind: io::ErrorKind) {
    assert_eq!(result.unwrap_err().kind(), kind);
}

pub fn atomically<R>(f: impl FnOnce() -> R) -> R {
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
    let _guard = LOCK.lock().unwrap();
    f()
}

#[test]
#[ignore]
fn tools_nofile() {
    let lim = rlimit::increase_nofile_limit(u64::MAX).unwrap();
    dbg!(lim);
}
