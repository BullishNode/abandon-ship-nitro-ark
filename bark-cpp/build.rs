use std::path::PathBuf;

fn resolved_bark_wallet_metadata() -> (String, String) {
    let lockfile_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let lockfile = std::fs::read_to_string(&lockfile_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", lockfile_path.display()));
    let lockfile: toml::Value = toml::from_str(&lockfile)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", lockfile_path.display()));
    let packages = lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock is missing its package list");
    let bark_packages: Vec<_> = packages
        .iter()
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("bark-wallet"))
        .collect();

    assert_eq!(
        bark_packages.len(),
        1,
        "expected exactly one resolved bark-wallet package in Cargo.lock"
    );

    let version = bark_packages[0]
        .get("version")
        .and_then(toml::Value::as_str)
        .expect("resolved bark-wallet package is missing its version")
        .to_owned();
    let source = bark_packages[0]
        .get("source")
        .and_then(toml::Value::as_str)
        .expect("resolved bark-wallet package is missing its exact Git source");
    let (_, revision) = source.rsplit_once('#')
        .expect("resolved bark-wallet Git source is missing its revision");
    assert!(source.starts_with("git+") && revision.len() == 40
        && revision.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "resolved bark-wallet source must identify an exact Git commit");
    (version, source.to_owned())
}

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/cxx.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
    let (version, source) = resolved_bark_wallet_metadata();
    println!("cargo:rustc-env=BARK_WALLET_VERSION={version}");
    println!("cargo:rustc-env=BARK_WALLET_SOURCE={source}");

    cxx_build::bridge("src/cxx.rs")
        .flag_if_supported("-std=c++17")
        .compile("arkcxxbridge");
}
