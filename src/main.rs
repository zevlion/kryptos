use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::fs;

#[derive(Parser)]
#[command(name = "kryptos", version = "1.0", about = "Powerful Cryptography Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt { input: String, output: String },
    Decrypt { input: String, output: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            let plaintext = fs::read(&input).context("Failed to read input file")?;

            let encrypted_data = encrypt(&plaintext, password.into())?;
            fs::write(output, encrypted_data).context("Failed to write encrypted file")?;
            println!("Encryption successful.");
        }
        Commands::Decrypt { input, output } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            let ciphertext = fs::read(&input).context("Failed to read encrypted file")?;

            let decrypted_data = decrypt(&ciphertext, password.into())?;
            fs::write(output, decrypted_data).context("Failed to write decrypted file")?;
            println!("Decryption successful.");
        }
    }
    Ok(())
}

fn derive_key(password: &SecretString, salt: &SaltString) -> Result<aes_gcm::Key<Aes256Gcm>> {
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.expose_secret().as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("KDF error: {}", e))?;

    let hash_output = password_hash.hash.context("Failed to get hash bytes")?;
    let key_bytes = hash_output.as_bytes();

    Ok(*aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes[..32]))
}

fn encrypt(plaintext: &[u8], password: SecretString) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);
    let key = derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

    let mut result = salt.to_string().into_bytes();
    result.push(b':');
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt(data: &[u8], password: SecretString) -> Result<Vec<u8>> {
    let parts: Vec<&[u8]> = data.splitn(2, |&b| b == b':').collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid encrypted file format");
    }

    let salt_str = std::str::from_utf8(parts[0])?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| anyhow::anyhow!(e))?;

    let remaining = parts[1];
    if remaining.len() < 12 {
        anyhow::bail!("Ciphertext too short");
    }

    let (nonce_bytes, ciphertext) = remaining.split_at(12);

    let key = derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption error: {}. Wrong password?", e))
}
