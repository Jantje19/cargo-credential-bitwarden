# cargo-credential-bitwarden

A Cargo [credential provider] for [Bitwarden].

This crate borrows heavily from the [cargo-credential-1password](https://crates.io/crates/cargo-credential-1password) crate.

## Usage

`cargo-credential-bitwarden` uses the Bitwarden `bw` CLI to store the token. You
must install the `bw` CLI from the [Bitwarden
website](https://bitwarden.com/help/cli/).

Afterward you need to configure `cargo` to use `cargo-credential-bitwarden` as
the credential provider. You can do this by adding something like the following
to your [cargo config file][credential provider]:

```toml
[registry]
global-credential-providers = ["cargo-credential-bitwarden --sync"]
```

Finally, run `cargo login` to save your registry token in Bitwarden.

## CLI Arguments

`cargo-credential-bitwarden` supports the following command-line arguments:

- `--email`: The email address used to login.
- `--sync`: Automatically sync the local vault before getting the credential and automatically sync when the credential gets updated.

[Bitwarden]: https://bitwarden.com/
[credential provider]: https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html
