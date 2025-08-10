use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use argon2::Argon2;
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, TryRngCore};
use rpassword::prompt_password;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use walkdir::WalkDir;

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;

#[derive(Debug, Parser)]
#[command(
    name = "filecrypt",
    version,
    about = "Encrypt/decrypt files with Argon2 + AES-GCM"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt a file or directory
    Encrypt {
        /// Input path (file or directory)
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path (file or directory)
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
    },
    /// Decrypt a file or directory
    Decrypt {
        /// Input path (file or directory)
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path (file or directory)
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
    },
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 failure");
    key
}

fn encrypt_file(path: &Path, out_dir: &Path, password: &str) -> std::io::Result<()> {
    let data = fs::read(path)?;
    let mut salt = [0u8; SALT_LEN];
    OsRng.try_fill_bytes(&mut salt).unwrap();
    let key = derive_key(password, &salt);

    let rel_name = path.file_name().unwrap().to_string_lossy();
    let name_bytes = rel_name.as_bytes();
    let mut plaintext = Vec::with_capacity(2 + name_bytes.len() + data.len());
    plaintext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(name_bytes);
    plaintext.extend_from_slice(&data);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce).unwrap();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .expect("encryption failure");

    let out_name = Uuid::new_v4().to_string() + ".enc";
    let out_path = out_dir.join(out_name);
    fs::create_dir_all(out_dir)?;
    let mut f = fs::File::create(out_path)?;
    f.write_all(&salt)?;
    f.write_all(&nonce)?;
    f.write_all(&ciphertext)?;
    Ok(())
}

fn decrypt_file(path: &Path, out_dir: &Path, password: &str) -> std::io::Result<()> {
    let buf = fs::read(path)?;
    let salt = &buf[..SALT_LEN];
    let nonce = &buf[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &buf[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("decryption failure");

    let name_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let name = std::str::from_utf8(&plaintext[2..2 + name_len]).unwrap();
    let file_data = &plaintext[2 + name_len..];

    let out_path = out_dir.join(name);
    fs::create_dir_all(out_dir)?;
    fs::write(out_path, file_data)?;
    Ok(())
}

fn process_dir(input: &Path, output: &Path, password: &str, encrypt: bool) -> std::io::Result<()> {
    for entry in WalkDir::new(input)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let in_path = entry.path();
        let rel = in_path.strip_prefix(input).unwrap();
        let out_subdir = output.join(rel.parent().unwrap_or_else(|| Path::new("")));
        if encrypt {
            encrypt_file(in_path, &out_subdir, password)?;
        } else {
            decrypt_file(in_path, &out_subdir, password)?;
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let password = prompt_password("Enter encryption password: ").expect("Password input failed");
    match cli.command {
        Commands::Encrypt { input, output } => {
            if input.is_file() {
                encrypt_file(&input, &output, &password)?;
            } else {
                process_dir(&input, &output, &password, true)?;
            }
        }
        Commands::Decrypt { input, output } => {
            if input.is_file() {
                decrypt_file(&input, &output, &password)?;
            } else {
                process_dir(&input, &output, &password, false)?;
            }
        }
    }
    Ok(())
}

// Run:
//   ./target/release/filecrypt encrypt <INPUT> <OUTPUT>
//   ./target/release/filecrypt decrypt <INPUT> <OUTPUT>
