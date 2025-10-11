use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use tempfile::NamedTempFile;

use crate::git::{config::GpgFormat, Config};

use super::Signer;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing signing key")]
    MissingSigningKey,
}

pub struct SshSigner<'c> {
    signing_key: &'c str,
    program: Option<&'c str>,
}

impl<'c> SshSigner<'c> {
    pub fn new(signing_key: &'c str, program: Option<&'c str>) -> Self {
        Self {
            signing_key,
            program,
        }
    }

    pub fn from_config(config: &'c Config) -> Result<Self, Error> {
        let signing_key = config
            .user
            .signing_key
            .as_ref()
            .ok_or(Error::MissingSigningKey)?;

        Ok(Self::new(
            signing_key,
            config.gpg.format.as_ref().and_then(|format| match format {
                GpgFormat::Ssh => config
                    .gpg
                    .config
                    .get("ssh")
                    .and_then(|config| config.program.as_deref()),
            }),
        ))
    }
}

impl Signer for SshSigner<'_> {
    fn sign(&self, content: &git2::Buf) -> Result<String, Box<dyn std::error::Error>> {
        // If the signing key is a public key (not a path) we have to write it to a file
        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(self.signing_key.as_bytes())?;
        tmp.flush()?;

        let program = self.program.unwrap_or("ssh-keygen");
        let signing_key_path: PathBuf = self.signing_key.into();

        // See: https://github.com/git/git/blob/34b6ce9b30747131b6e781ff718a45328aa887d0/gpg-interface.c#L1072
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(if signing_key_path.exists() {
                &signing_key_path
            } else {
                tmp.path()
            })
            .spawn()?;

        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(content)?;
        stdin.flush()?;

        let output = child.wait_with_output()?;

        if !output.status.success() {
            return Err(format!("failed to sign: {}", String::from_utf8(output.stderr)?).into());
        }

        Ok(String::from_utf8(output.stdout)?)
    }
}
