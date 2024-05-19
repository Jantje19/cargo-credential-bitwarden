//! Cargo registry Bitwarden credential process.

use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, Error, RegistryInfo, Secret,
};
use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::process::{Command, Stdio};
use url::Url;

/// Implementation of Bitwarden Vault access for Cargo registries.
struct BitwardenVault {
    email_address: Option<String>,
    cmd_name: String,
    auto_sync: bool,
}

/// Bitwarden item from `bw list items`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListItem {
    id: String,
    r#type: u32,
    name: String,
    login: LoginItem,
}
/// Bitwarden login item from `ListItem::login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginItem {
    username: Option<String>,
    password: String,
    uris: Vec<Uri>,
}
/// Bitwarden URI for login item
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Uri {
    r#match: Option<u32>,
    uri: String,
}

/// Bitwarden item for `bw create item`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListItemCreateRequest {
    name: String,
    login: LoginItem,
    r#type: u32,
}

impl BitwardenVault {
    fn new(args: &[&str]) -> Result<BitwardenVault, Error> {
        let mut args = args.iter();
        let mut email_address = None;
        let mut auto_sync = false;
        while let Some(arg) = args.next() {
            match *arg {
                "--email" => {
                    email_address = Some(args.next().ok_or("--email needs an arg")?);
                }
                "--sync" => {
                    auto_sync = true;
                }
                s if s.starts_with('-') => {
                    return Err(format!("unknown option {}", s).into());
                }
                _ => {
                    return Err("too many arguments".into());
                }
            }
        }

        Ok(BitwardenVault {
            email_address: email_address.map(|s| s.to_string()),
            cmd_name: Self::get_cmd_name(),
            auto_sync,
        })
    }

    fn get_cmd_name() -> String {
        fn command_exists(command: &str) -> bool {
            let mut cmd = Command::new(command);
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
            match cmd.spawn() {
                Ok(_) => true,
                Err(e) => match e.kind() {
                    ErrorKind::NotFound => false,
                    _ => panic!("{}", e),
                },
            }
        }

        let cmd = "bw";
        if command_exists(cmd) {
            return String::from(cmd);
        }

        cfg_if! {
            if #[cfg(target_os = "windows")] {
                let cmd = "bw.cmd";
                if command_exists(cmd) {
                    return String::from(cmd);
                }
            }
        }

        panic!("Could not find Bitwarden CLI");
    }

    fn signin(&self) -> Result<Option<String>, Error> {
        // If there are any session env vars, we'll assume that this is the orrect account,
        // and that the user knows what they are doing.
        if std::env::vars().any(|(name, _)| name == "BW_SESSION") {
            return Ok(None);
        }

        let mut cmd = Command::new(&self.cmd_name);
        cmd.args(["login", "--raw"]);
        if let Some(email_address) = &self.email_address {
            cmd.arg(email_address);
        }

        cmd.stdout(Stdio::piped());

        let mut child: std::process::Child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn `bw`: {}", e))?;

        let mut buffer = String::new();

        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("failed to get session from `bw`: {}", e))?;

        if let Some(end) = buffer.find('\n') {
            buffer.truncate(end);
        }

        let status = child
            .wait()
            .map_err(|e| format!("failed to wait for `bw`: {}", e))?;

        if !status.success() {
            return Err(format!("failed to run `bw login`: {}", status).into());
        }

        Ok(Some(buffer))
    }

    fn make_cmd(&self, session: &Option<String>, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.cmd_name);
        cmd.arg("--nointeraction");
        cmd.arg("--cleanexit");

        if let Some(session) = session {
            cmd.arg("--session");
            cmd.arg(session);
        }

        cmd.args(args);
        cmd
    }

    fn run_cmd(&self, mut cmd: Command) -> Result<String, Error> {
        cmd.stdout(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn `bw`: {}", e))?;

        let mut buffer = String::new();

        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("failed to read `bw` output: {}", e))?;

        let status = child
            .wait()
            .map_err(|e| format!("failed to wait for `bw`: {}", e))?;

        if !status.success() {
            return Err(format!("`bw` command exit error: {}", status).into());
        }

        Ok(buffer)
    }

    fn search(&self, session: &Option<String>, index_url: &str) -> Result<Option<ListItem>, Error> {
        self.sync(session)?;

        let cmd = self.make_cmd(session, &["list", "items", "--url", index_url]);
        let buffer = self.run_cmd(cmd)?;

        let items: Vec<ListItem> = serde_json::from_str(&buffer)
            .map_err(|e| format!("failed to deserialize JSON from Bitwarden list: {}", e))?;
        let mut items = items
            .into_iter()
            .filter(|item| item.login.uris.iter().any(|uri| uri.uri == index_url));

        match items.next() {
            Some(item) => {
                // Should this maybe just sort on `updatedAt` and return the newest one?
                if items.next().is_some() {
                    return Err(format!(
                        "too many Bitwarden logins match registry `{}`, consider deleting the excess entries",
                        index_url
                    )
                    .into());
                }
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }

    fn modify(
        &self,
        session: &Option<String>,
        item: &ListItem,
        token: Secret<&str>,
        name: &Option<&str>,
    ) -> Result<(), Error> {
        let request = {
            let mut item = item.clone();
            item.login.password = token.expose().to_string();
            if let Some(name) = name {
                item.name = name.to_string();
            }
            item
        };

        let data = serde_json::to_string(&request)
            .map_err(|e| format!("failed to deserialize new item: {}", e))?;
        let encoded = self.encode(session, data.as_bytes())?;

        let cmd = self.make_cmd(session, &["edit", "item", &item.id, &encoded]);
        self.run_cmd(cmd)?;
        self.sync(session)?;
        Ok(())
    }

    fn create(
        &self,
        session: &Option<String>,
        index_url: &str,
        token: Secret<&str>,
        name: &Option<&str>,
    ) -> Result<(), Error> {
        let name = {
            let name = match name {
                Some(name) => name.to_string(),
                None => match Url::parse(index_url) {
                    Ok(url) => url.host().unwrap().to_string(),
                    Err(_) => String::from("<unknown>"),
                },
            };

            format!("Cargo registry token for {}", name)
        };

        let request = ListItemCreateRequest {
            name,
            r#type: 1, // login type
            login: LoginItem {
                password: token.expose().to_string(),
                username: None,
                uris: Vec::from(&[Uri {
                    uri: index_url.to_string(),
                    r#match: Some(1), // match by host
                }]),
            },
        };

        let data = serde_json::to_vec(&request)
            .map_err(|e| format!("failed to deserialize new item: {}", e))?;
        let encoded = self.encode(session, &data)?;

        let cmd = self.make_cmd(session, &["create", "item", &encoded]);
        self.run_cmd(cmd)?;
        self.sync(session)?;
        Ok(())
    }

    fn delete(&self, session: &Option<String>, id: &str) -> Result<(), Error> {
        let cmd = self.make_cmd(session, &["delete", "item", id]);
        self.run_cmd(cmd)?;
        self.sync(session)?;
        Ok(())
    }

    fn sync(&self, session: &Option<String>) -> Result<(), Error> {
        if !self.auto_sync {
            return Ok(());
        }

        let cmd = self.make_cmd(session, &["sync"]);
        self.run_cmd(cmd)?;
        Ok(())
    }

    fn encode(&self, session: &Option<String>, data: &[u8]) -> Result<String, Error> {
        let mut cmd = self.make_cmd(session, &["encode"]);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn `bw`: {}", e))?;

        {
            let child_stdin = child.stdin.as_mut().unwrap();
            child_stdin
                .write_all(data)
                .map_err(|e| format!("failed to write to stdin: {}", e))?;
        }

        let status = child
            .wait()
            .map_err(|e| format!("failed to wait for `bw`: {}", e))?;

        let mut buffer = String::new();

        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("failed to read `bw` output: {}", e))?;

        if !status.success() {
            return Err(format!("`bw` command exit error: {}", status).into());
        }

        Ok(buffer)
    }
}

pub struct BitwardenCredential;

impl Credential for BitwardenCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, Error> {
        let op = BitwardenVault::new(args)?;
        match action {
            Action::Get(_) => {
                let session = op.signin()?;
                if let Some(item) = op.search(&session, registry.index_url)? {
                    Ok(CredentialResponse::Get {
                        token: Secret::from(item.login.password),
                        cache: CacheControl::Session,
                        operation_independent: true,
                    })
                } else {
                    Err(Error::NotFound)
                }
            }
            Action::Login(options) => {
                let session = op.signin()?;
                // Check if an item already exists.
                if let Some(item) = op.search(&session, registry.index_url)? {
                    eprintln!("note: token already exists for `{}`", registry.index_url);
                    let token = cargo_credential::read_token(options, registry)?;
                    op.modify(&session, &item, token.as_deref(), &registry.name)?;
                } else {
                    let token = cargo_credential::read_token(options, registry)?;
                    op.create(
                        &session,
                        registry.index_url,
                        token.as_deref(),
                        &registry.name,
                    )?;
                }
                Ok(CredentialResponse::Login)
            }
            Action::Logout => {
                let session = op.signin()?;
                // Check if an item already exists.
                if let Some(item) = op.search(&session, registry.index_url)? {
                    op.delete(&session, &item.id)?;
                    Ok(CredentialResponse::Logout)
                } else {
                    Err(Error::NotFound)
                }
            }
            _ => Err(Error::OperationNotSupported),
        }
    }
}

fn main() {
    cargo_credential::main(BitwardenCredential);
}
