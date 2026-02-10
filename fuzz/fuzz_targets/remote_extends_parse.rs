#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct RemoteExtendsInput {
    repo: String,
    commit_ref: String,
    url: String,
    https_only: bool,
}

fn trim_input(s: &str) -> String {
    s.chars().take(512).collect()
}

fuzz_target!(|input: RemoteExtendsInput| {
    let repo = trim_input(&input.repo);
    let commit_ref = trim_input(&input.commit_ref);
    let url = trim_input(&input.url);

    let _ = hushd::remote_extends::security_parse_git_remote_host(&repo, input.https_only);
    let _ = hushd::remote_extends::security_validate_git_commit_ref(&commit_ref);
    let _ = hushd::remote_extends::security_parse_remote_url(&url, input.https_only);
});
