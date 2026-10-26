use omp_core::{parse_and_validate, Manifest};
use omp_manifest::{CreateManifest, PublicKeyDocument};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyDocument {
    key_id: String,
    algorithm: String,
    private_key_base64url: String,
    public_key_base64url: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };
    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "keygen" => keygen(&rest),
        "pack" | "package" => pack(&rest),
        "inspect" => inspect(&rest),
        "verify" => verify(&rest),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => Err(input_error(format!("unknown command `{command}`")).into()),
    }
}

fn keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (positional, flags) = arguments(args)?;
    if !positional.is_empty() {
        return Err(input_error("keygen takes no positional arguments").into());
    }
    reject_unknown(&flags, &["key-id", "private", "public"])?;
    let key_id = flag(&flags, "key-id").unwrap_or("local-key-01");
    if key_id.is_empty() {
        return Err(input_error("--key-id must not be empty").into());
    }
    let private_path = Path::new(flag(&flags, "private").unwrap_or("omp-key.private.json"));
    let public_path = Path::new(flag(&flags, "public").unwrap_or("omp-key.public.json"));
    if private_path == public_path {
        return Err(input_error("private and public paths must differ").into());
    }

    let key = omp_crypto::generate_signing_key();
    let public_key = omp_crypto::encode_base64url(key.verifying_key().as_bytes());
    let private = PrivateKeyDocument {
        key_id: key_id.into(),
        algorithm: "Ed25519".into(),
        private_key_base64url: omp_crypto::encode_base64url(&key.to_bytes()),
        public_key_base64url: public_key.clone(),
    };
    let public = PublicKeyDocument {
        key_id: key_id.into(),
        algorithm: "Ed25519".into(),
        public_key_base64url: public_key,
    };
    write_new_private(private_path, &json_line(&private)?)?;
    if let Err(error) = write_new(public_path, &json_line(&public)?) {
        let _ = fs::remove_file(private_path);
        return Err(error.into());
    }
    println!("created private key: {}", private_path.display());
    println!("created public key:  {}", public_path.display());
    Ok(())
}

fn pack(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (positional, flags) = arguments(args)?;
    if positional.len() != 1 {
        return Err(input_error("pack requires exactly one audio file").into());
    }
    reject_unknown(
        &flags,
        &[
            "manifest-id",
            "recording-id",
            "work-id",
            "release-id",
            "issuer-id",
            "agreement-id",
            "license-id",
            "asset-id",
            "private-key",
            "output",
            "created-at",
        ],
    )?;
    let audio = Path::new(&positional[0]);
    let media_type = media_type(audio)?;
    let private_path = Path::new(required(&flags, "private-key")?);
    let private: PrivateKeyDocument = strict_document(&fs::read(private_path)?)?;
    if private.algorithm != "Ed25519" {
        return Err(input_error("private key algorithm must be Ed25519").into());
    }
    let key = omp_crypto::signing_key_from_base64url(&private.private_key_base64url)?;
    if omp_crypto::encode_base64url(key.verifying_key().as_bytes()) != private.public_key_base64url
    {
        return Err(input_error("private key document has mismatched public key").into());
    }
    let created_at = match flag(&flags, "created-at") {
        Some(value) => value.to_owned(),
        None => OffsetDateTime::now_utc().format(&Rfc3339)?,
    };
    let input = CreateManifest {
        manifest_id: required(&flags, "manifest-id")?,
        recording_id: required(&flags, "recording-id")?,
        work_id: required(&flags, "work-id")?,
        release_id: flag(&flags, "release-id"),
        issuer_id: required(&flags, "issuer-id")?,
        agreement_id: required(&flags, "agreement-id")?,
        license_id: required(&flags, "license-id")?,
        asset_id: flag(&flags, "asset-id").unwrap_or("primary-audio"),
        media_type,
        created_at: &created_at,
        key_id: &private.key_id,
    };
    let manifest = omp_manifest::create_signed(audio, &input, &key)?;
    let output = flag(&flags, "output")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}.omc.json", audio.display())));
    write_new(&output, &omp_manifest::to_pretty_json(&manifest)?)?;
    println!("created manifest: {}", output.display());
    Ok(())
}

fn inspect(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (positional, flags) = arguments(args)?;
    reject_unknown(&flags, &[])?;
    if positional.len() != 1 {
        return Err(input_error("inspect requires exactly one manifest file").into());
    }
    let manifest: Manifest = parse_and_validate(&fs::read(&positional[0])?)?;
    println!("manifest_id:  {}", manifest.manifest_id);
    println!("recording_id: {}", manifest.recording_id);
    println!("issuer_id:    {}", manifest.issuer_id);
    println!("created_at:   {}", manifest.created_at);
    println!("key_id:       {}", manifest.signature.key_id);
    for asset in manifest.assets {
        println!(
            "asset:        {} {} bytes {} {}",
            asset.asset_id, asset.size_bytes, asset.sha256, asset.media_type
        );
    }
    println!("signature:    present (not verified by inspect)");
    Ok(())
}

fn verify(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (positional, flags) = arguments(args)?;
    reject_unknown(&flags, &["public-key"])?;
    if positional.len() != 2 {
        return Err(input_error("verify requires <audio-file> <manifest.json>").into());
    }
    let (audio, manifest_path) =
        if positional[0].ends_with(".json") && !positional[1].ends_with(".json") {
            (Path::new(&positional[1]), Path::new(&positional[0]))
        } else {
            (Path::new(&positional[0]), Path::new(&positional[1]))
        };
    let trusted_key: PublicKeyDocument =
        strict_document(&fs::read(required(&flags, "public-key")?)?)?;
    let manifest = omp_manifest::verify_signature(&fs::read(manifest_path)?, &trusted_key)?;
    omp_manifest::verify_asset(&manifest, audio, media_type(audio)?)?;
    println!("verified: signature and audio bytes are valid");
    Ok(())
}

fn strict_document<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let value = omp_core::parse_value(bytes)?;
    Ok(serde_json::from_value(value)?)
}

fn arguments(args: &[String]) -> Result<(Vec<String>, HashMap<String, String>), io::Error> {
    let mut positional = Vec::new();
    let mut flags = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        if let Some(name) = value.strip_prefix("--") {
            if name.is_empty() {
                return Err(input_error("empty flag"));
            }
            index += 1;
            let Some(flag_value) = args.get(index) else {
                return Err(input_error(format!("--{name} requires a value")));
            };
            if flag_value.starts_with("--") {
                return Err(input_error(format!("--{name} requires a value")));
            }
            if flags.insert(name.to_owned(), flag_value.clone()).is_some() {
                return Err(input_error(format!("duplicate --{name}")));
            }
        } else {
            positional.push(value.clone());
        }
        index += 1;
    }
    Ok((positional, flags))
}

fn reject_unknown(flags: &HashMap<String, String>, allowed: &[&str]) -> Result<(), io::Error> {
    for name in flags.keys() {
        if !allowed.contains(&name.as_str()) {
            return Err(input_error(format!("unknown option --{name}")));
        }
    }
    Ok(())
}
fn required<'a>(flags: &'a HashMap<String, String>, name: &str) -> Result<&'a str, io::Error> {
    flag(flags, name).ok_or_else(|| input_error(format!("missing required --{name}")))
}
fn flag<'a>(flags: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    flags.get(name).map(String::as_str)
}
fn input_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn json_line<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    file.sync_all()
}

#[cfg(unix)]
fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    file.sync_all()
}
#[cfg(not(unix))]
fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_new(path, bytes)
}

fn media_type(path: &Path) -> Result<&'static str, io::Error> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "flac" => Ok("audio/flac"),
        "mp3" => Ok("audio/mpeg"),
        "ogg" | "oga" => Ok("audio/ogg"),
        "wav" | "wave" => Ok("audio/wav"),
        "m4a" | "mp4" => Ok("audio/mp4"),
        _ => Err(input_error(
            "unsupported audio extension; expected flac, mp3, ogg/oga, wav/wave, or m4a/mp4",
        )),
    }
}

fn print_help() {
    println!("OMP Core v0.1 (offline)\n\nCommands:\n  omp keygen [--key-id ID] [--private FILE] [--public FILE]\n  omp pack AUDIO --manifest-id ID --recording-id ID --work-id ID --issuer-id ID \\\n+    --agreement-id ID --license-id ID --private-key FILE [--output FILE]\n  omp inspect MANIFEST\n  omp verify AUDIO MANIFEST --public-key FILE\n\nAll output files use create-new semantics and are never silently overwritten.");
}
