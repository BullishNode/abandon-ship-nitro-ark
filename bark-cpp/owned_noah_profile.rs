//! Build-time public bindings for the explicit owned signet profile.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

const PROFILE: &str = "track-a-two-step-per-key";
const SIGNET: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
pub struct Profile {
    pub domain: String,
    pub ca_pem: Vec<u8>,
    pub routing_sha256: String,
    pub ca_sha256: String,
}
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fail<T>() -> Result<T> {
    Err("Invalid owned signet public build binding".into())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return fail();
    }
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit {
        return fail();
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > limit
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || after.len() != bytes.len() as u64
    {
        return fail();
    }
    Ok(bytes)
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing public build field".into())
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn verify_ca(bytes: &[u8]) -> Result<()> {
    let pem = std::str::from_utf8(bytes)?;
    if pem.matches("-----BEGIN CERTIFICATE-----").count() != 1
        || pem.matches("-----END CERTIFICATE-----").count() != 1
        || pem.contains("PRIVATE KEY")
    {
        return fail();
    }
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    let output = Command::new("openssl")
        .args(["verify", "-check_ss_sig", "-purpose", "any", "-CAfile"])
        .arg(tmp.path())
        .arg(tmp.path())
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return fail();
    }
    let output = Command::new("openssl")
        .args(["x509", "-noout", "-ext", "basicConstraints", "-in"])
        .arg(tmp.path())
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || !String::from_utf8(output.stdout)?.contains("CA:TRUE") {
        return fail();
    }
    Ok(())
}
pub fn validate(
    routing: &[u8],
    routing_sha: &str,
    ca: &[u8],
    ca_sha: &str,
    sdk: &str,
    expected_nitro: &str,
) -> Result<Profile> {
    if !digest(routing_sha) || !digest(ca_sha) || hash(routing) != routing_sha || hash(ca) != ca_sha
    {
        return fail();
    }
    let value: Value = serde_json::from_slice(routing)?;
    if value.get("schema").and_then(Value::as_u64) != Some(1)
        || text(&value, "profile")? != PROFILE
        || text(&value, "network")? != "signet"
        || text(&value, "genesis")? != SIGNET
        || text(&value, "sdk_commit")? != sdk
    {
        return fail();
    }
    let nitro = text(&value, "nitro_commit")?;
    if nitro != expected_nitro
        || nitro.len() != 40
        || !nitro
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return fail();
    }
    let key = text(&value, "server_pubkey")?;
    if key.len() != 66
        || !key.bytes().all(|c| c.is_ascii_hexdigit())
        || !(key.starts_with("02") || key.starts_with("03"))
    {
        return fail();
    }
    let url = url::Url::parse(text(&value, "api_url")?)?;
    let domain = text(&value, "lnurl_domain")?;
    if url.scheme() != "https"
        || url.host_str() != Some(domain)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || domain == "noahwallet.io"
        || domain.ends_with(".noahwallet.io")
        || domain.ends_with(".2nd.dev")
    {
        return fail();
    }
    verify_ca(ca)?;
    Ok(Profile {
        domain: domain.to_owned(),
        ca_pem: ca.to_vec(),
        routing_sha256: routing_sha.to_owned(),
        ca_sha256: ca_sha.to_owned(),
    })
}
#[cfg(not(test))]
pub fn from_environment() -> Result<Profile> {
    if std::env::var("NOAH_ARK_PROFILE")? != PROFILE {
        return fail();
    }
    let path = std::env::var("NOAH_A_ROUTING_MANIFEST")?;
    let ca_path = std::env::var("NOAH_A_CA_FILE")?;
    let routing = bounded(Path::new(&path), 65536)?;
    let ca = bounded(Path::new(&ca_path), 16384)?;
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rerun-if-changed={ca_path}");
    let manifest: toml::Value =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?
            .parse()?;
    let sdk = manifest
        .get("dependencies")
        .and_then(|x| x.get("bark-wallet"))
        .and_then(|x| x.get("rev"))
        .and_then(toml::Value::as_str)
        .ok_or("Missing owned SDK revision")?;
    validate(
        &routing,
        &std::env::var("NOAH_A_ROUTING_SHA256")?,
        &ca,
        &std::env::var("NOAH_A_CA_SHA256")?,
        sdk,
        &std::env::var("NOAH_ARK_NITRO_COMMIT")?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const CA: &[u8] = include_bytes!("test-fixtures/synthetic-public-ca.crt");
    const SDK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NITRO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn fixture() -> Value {
        serde_json::json!({"schema":1,"profile":PROFILE,"network":"signet","genesis":SIGNET,"server_pubkey":format!("02{}", "c".repeat(64)),"sdk_commit":SDK,"nitro_commit":NITRO,"api_url":"https://owned-noah.example.test","lnurl_domain":"owned-noah.example.test","wallet":{"bitcoind_pass":"synthetic-not-embedded"}})
    }
    fn check(v: &Value) -> Result<Profile> {
        let bytes = serde_json::to_vec(v)?;
        validate(&bytes, &hash(&bytes), CA, &hash(CA), SDK, NITRO)
    }
    #[test]
    fn owned_noah_build_public_projection_excludes_wallet_credentials() {
        let p = check(&fixture()).unwrap();
        assert_eq!(p.domain, "owned-noah.example.test");
        assert_eq!(p.ca_pem, CA);
        assert_eq!(p.ca_sha256, hash(CA));
        assert!(digest(&p.routing_sha256));
    }
    #[test]
    fn owned_noah_build_refuses_wrong_profile_network_source_or_identity() {
        for (field, value) in [
            ("profile", "stock"),
            ("network", "mainnet"),
            ("genesis", "wrong"),
            ("sdk_commit", "wrong"),
            ("nitro_commit", "wrong"),
            ("server_pubkey", "invalid"),
        ] {
            let mut v = fixture();
            v[field] = Value::String(value.into());
            assert!(check(&v).is_err());
        }
    }
    #[test]
    fn owned_noah_build_refuses_domain_drift_or_unsafe_origin() {
        for origin in [
            "http://owned-noah.example.test",
            "https://foreign.example.test",
            "https://user@owned-noah.example.test",
            "https://owned-noah.example.test/path",
            "https://owned-noah.example.test:444",
        ] {
            let mut v = fixture();
            v["api_url"] = Value::String(origin.into());
            assert!(check(&v).is_err());
        }
    }
    #[test]
    fn owned_noah_build_refuses_stock_noah_origin() {
        let mut v = fixture();
        v["api_url"] = Value::String("https://signet.noahwallet.io".into());
        v["lnurl_domain"] = Value::String("signet.noahwallet.io".into());
        assert!(check(&v).is_err());
    }
    #[test]
    fn owned_noah_build_refuses_wrong_external_hashes_or_malformed_ca() {
        let bytes = serde_json::to_vec(&fixture()).unwrap();
        assert!(validate(&bytes, &"0".repeat(64), CA, &hash(CA), SDK, NITRO).is_err());
        assert!(validate(&bytes, &hash(&bytes), CA, &"0".repeat(64), SDK, NITRO).is_err());
        assert!(
            validate(
                &bytes,
                &hash(&bytes),
                b"invalid",
                &hash(b"invalid"),
                SDK,
                NITRO
            )
            .is_err()
        );
    }
    #[test]
    fn owned_noah_build_refuses_missing_fields() {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove("lnurl_domain");
        assert!(check(&v).is_err());
    }
    #[test]
    fn owned_noah_build_bounded_reader_refuses_overflow() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0; 17]).unwrap();
        assert!(bounded(f.path(), 16).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn owned_noah_build_bounded_reader_refuses_symlink() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("ca");
        std::fs::write(&f, CA).unwrap();
        let link = d.path().join("alias");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(bounded(&link, 16384).is_err());
    }
}
