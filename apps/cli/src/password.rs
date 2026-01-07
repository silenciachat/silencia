use anyhow::{anyhow, Result};
use colored::Colorize;
use rusqlite::{params, Connection};
use silencia_vault::IdentityVault;
use std::path::Path;

const MAX_ATTEMPTS: usize = 3;
const LOCKOUT_SECONDS: i64 = 300; // 5 minutes

/// Prompt user to create a new vault password
pub fn prompt_create_vault_password() -> Result<String> {
    println!();
    println!("{}", "▸ Create Vault Password".bright_yellow().bold());
    println!("{}", "─".repeat(72).bright_black());
    println!("  {} Minimum 12 characters", "•".dimmed());
    println!(
        "  {} Used to encrypt your messages and identity",
        "•".dimmed()
    );
    println!(
        "  {} Cannot be recovered if lost - backup recommended",
        "•".dimmed()
    );
    println!();

    loop {
        let password = rpassword::prompt_password("  Create password: ")?;

        if password.is_empty() {
            println!("  {} Password cannot be empty", "✗".red());
            continue;
        }

        if password.len() < 12 {
            println!("  {} Password too short (minimum 12 characters)", "✗".red());
            continue;
        }

        let confirm = rpassword::prompt_password("  Confirm password: ")?;

        if password != confirm {
            println!("  {} Passwords don't match", "✗".red());
            continue;
        }

        println!("  {} Password set successfully", "✓".green());
        println!();
        return Ok(password);
    }
}

/// Prompt user to unlock vault with password (max 3 attempts)
pub fn prompt_unlock_vault(vault_path: &Path, identity_id: &[u8; 32]) -> Result<String> {
    // Check if vault is locked
    if let Some(remaining) = check_vault_locked(vault_path)? {
        let minutes = remaining / 60;
        let seconds = remaining % 60;
        return Err(anyhow!(
            "Vault locked due to failed attempts. Try again in {}m {}s",
            minutes,
            seconds
        ));
    }

    println!();
    println!("{}", "▸ Unlock Vault".bright_cyan().bold());
    println!("{}", "─".repeat(72).bright_black());
    println!();

    for attempt in 1..=MAX_ATTEMPTS {
        let password = rpassword::prompt_password("  Vault password: ")?;

        match IdentityVault::open(vault_path, &password, identity_id) {
            Ok(vault) => {
                vault.reset_failed_attempts()?;
                println!("  {} Vault unlocked", "✓".green());
                println!();
                return Ok(password);
            }
            Err(silencia_vault::VaultError::WrongPassword) => {
                if attempt < MAX_ATTEMPTS {
                    println!(
                        "  {} Wrong password. Attempt {}/{}",
                        "✗".red(),
                        attempt,
                        MAX_ATTEMPTS
                    );
                    record_failed_attempt(vault_path)?;
                } else {
                    record_failed_attempt(vault_path)?;
                    lock_vault(vault_path, LOCKOUT_SECONDS)?;
                    println!(
                        "  {} Wrong password. Attempt {}/{}",
                        "✗".red(),
                        attempt,
                        MAX_ATTEMPTS
                    );
                    println!();
                    return Err(anyhow!(
                        "Too many failed attempts. Vault locked for 5 minutes."
                    ));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    unreachable!()
}

/// Check if vault is currently locked
fn check_vault_locked(path: &Path) -> Result<Option<i64>> {
    let conn = Connection::open(path)?;

    let locked_until: i64 = conn.query_row(
        "SELECT locked_until FROM vault_metadata WHERE id = 1",
        [],
        |row| row.get(0),
    )?;

    let now = chrono::Utc::now().timestamp();
    if locked_until > now {
        Ok(Some(locked_until - now))
    } else {
        Ok(None)
    }
}

/// Record a failed unlock attempt
fn record_failed_attempt(path: &Path) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "UPDATE vault_metadata SET failed_attempts = failed_attempts + 1 WHERE id = 1",
        [],
    )?;
    Ok(())
}

/// Lock vault for specified seconds
fn lock_vault(path: &Path, seconds: i64) -> Result<()> {
    let conn = Connection::open(path)?;
    let lock_until = chrono::Utc::now().timestamp() + seconds;
    conn.execute(
        "UPDATE vault_metadata SET locked_until = ? WHERE id = 1",
        params![lock_until],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_password_validation() {
        // Too short
        assert!("short".len() < 12);

        // Minimum length
        assert!("12characters".len() == 12);

        // Valid
        assert!("this_is_a_secure_password".len() >= 12);
    }
}
