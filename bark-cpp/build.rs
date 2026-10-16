mod owned_noah_profile;

use std::path::PathBuf;

fn resolved_bark_wallet_version() -> String {
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

    bark_packages[0]
        .get("version")
        .and_then(toml::Value::as_str)
        .expect("resolved bark-wallet package is missing its version")
        .to_owned()
}

fn main() {
    for name in [
        "NOAH_ARK_PROFILE",
        "NOAH_A_ROUTING_MANIFEST",
        "NOAH_A_ROUTING_SHA256",
        "NOAH_A_CA_FILE",
        "NOAH_A_CA_SHA256",
        "NOAH_ARK_NITRO_COMMIT",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=owned_noah_profile.rs");
    if std::env::var("NOAH_ARK_PROFILE").ok().as_deref() == Some("track-a-two-step-per-key")
        && std::env::var_os("CARGO_FEATURE_OWNED_NOAH_SIGNET").is_none()
    {
        panic!("The owned Noah build profile requires its explicit native feature");
    }
    if std::env::var_os("CARGO_FEATURE_OWNED_NOAH_SIGNET").is_some() {
        let profile = owned_noah_profile::from_environment().unwrap_or_else(|_| {
            panic!("Invalid or missing hash-pinned owned Noah signet build inputs")
        });
        let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        std::fs::write(out.join("owned-noah-ca.pem"), profile.ca_pem)
            .expect("write public qualification CA");
        println!("cargo:rustc-env=NITRO_OWNED_NOAH_DOMAIN={}", profile.domain);
        println!(
            "cargo:rustc-env=NITRO_OWNED_NOAH_ROUTING_SHA256={}",
            profile.routing_sha256
        );
        println!(
            "cargo:rustc-env=NITRO_OWNED_NOAH_CA_SHA256={}",
            profile.ca_sha256
        );
    }
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/cxx.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!(
        "cargo:rustc-env=BARK_WALLET_VERSION={}",
        resolved_bark_wallet_version()
    );

    cxx_build::bridge("src/cxx.rs")
        .flag_if_supported("-std=c++17")
        .compile("arkcxxbridge");
}
