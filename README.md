# pwcheck

[![Crates.io][crates_img]][crates_lnk] [![Docs.rs][doc_img]][doc_lnk] [![CI][ci_img]][ci_lnk] [![RustC 1.64+][rustc_img]][rustc_lnk] 

[crates_img]: https://img.shields.io/crates/v/pwcheck.svg
[crates_lnk]: https://crates.io/crates/pwcheck
[doc_img]: https://docs.rs/pwcheck/badge.svg
[doc_lnk]: https://docs.rs/pwcheck
[ci_img]: https://github.com/chipsenkbeil/pwcheck/actions/workflows/ci.yml/badge.svg
[ci_lnk]: https://github.com/chipsenkbeil/pwcheck/actions/workflows/ci.yml
[rustc_img]: https://img.shields.io/badge/rustc_1.64.0+-lightgray.svg
[rustc_lnk]: https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html

Provides a singular function to check and validate the password of a local user
account on Linux, MacOS, and Windows.

## Install

```toml
[dependencies]
pwcheck = "0.2"
```

### Dependencies

* On `Linux`, this leverages PAM bindings and therefore requires PAM developer
  headersto be available. 
  * **Debian/Ubuntu:** `apt install libpam0g-dev`
  * **Fedora/CentOS:** `dnf install pam-devel` (you may also need `dnf install
    clang` if you get `stddef.h not found`)
* On `MacOS`, this leverages `dscl`, and does not need anything additional.
* On `Windows`, this leverages [windows-rs](https://crates.io/crates/windows)
  and does not need anything additional.

## Usage

```rust
use pwcheck::*;

fn main() {
    // Check if some username/password combo is valid
    match pwcheck("username", "password") {
        PwcheckResult::Ok => println!("Correct username & password!"),
        PwcheckResult::WrongPassword => println!("Incorrect username & password!"),
        PwcheckResult::Err(x) => println!("Encountered error: {x}"),
    }
}
```

## How It Works

### Linux

On Linux platforms, this leverages PAM with the login service to perform
authentication in a non-interactive fashion via a username and password.

You can specify a different service with the Linux module's implementation:

```rust,no_run
use pwcheck::PwcheckResult;

fn main() {
    #[cfg(target_os = "linux")]
    {
        use pwcheck::linux::{Method, pwcheck};
        match pwcheck(Method::Pam {
            username: "username",
            password: "password",
            service: "my-service",
        }) {
            PwcheckResult::Ok => println!("Correct username & password!"),
            PwcheckResult::WrongPassword => println!("Incorrect username & password!"),
            PwcheckResult::Err(x) => println!("Encountered error: {x}"),
        }
    }
}
```

### MacOS

On MacOS platforms, this leverages executing `dscl` to authenticate the user
using the datasource "." (local directory).

You can specify a different datasource with the MacOS module's implementation:

```rust,no_run
use pwcheck::PwcheckResult;

fn main() {
    #[cfg(target_os = "macos")]
    {
        use pwcheck::macos::{Method, pwcheck};
        match pwcheck::macos::pwcheck(Method::Dscl {
            username: "username", 
            password: "password", 
            datasource: "/Login/Default", 
            timeout: None,
        }) {
            PwcheckResult::Ok => println!("Correct username & password!"),
            PwcheckResult::WrongPassword => println!("Incorrect username & password!"),
            PwcheckResult::Err(x) => println!("Encountered error: {x}"),
        }
    }
}
```

### Windows

On Windows platforms, this leverages the [LogonUserW][LogonUserW] function to
attempt to log a user on to the local computer.

Note that this function requires the running program to have the
[SeTcbPrivilege privilege][SeTcbPrivilege] set in order to log in as a user
other than the user that started the program. So it's safe to use this to
validate the account of the user running this program, but otherwise it needs a
very high-level permission to validate the password, typically something you'd
see from running the program as an administrator.

```rust,no_run
use pwcheck::PwcheckResult;

fn main() {
    #[cfg(windows)]
    {
        use pwcheck::windows::{Method, pwcheck};
        match pwcheck::macos::pwcheck(Method::LogonUserW {
            username: "username", 
            password: "password", 
        }) {
            PwcheckResult::Ok => println!("Correct username & password!"),
            PwcheckResult::WrongPassword => println!("Incorrect username & password!"),
            PwcheckResult::Err(x) => println!("Encountered error: {x}"),
        }
    }
}
```

[LogonUserW]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
[SeTcbPrivilege]: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system

## License

This project is licensed under either of

Apache License, Version 2.0, (LICENSE-APACHE or
[apache-license][apache-license]) MIT license (LICENSE-MIT or
[mit-license][mit-license]) at your option.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
[mit-license]: http://opensource.org/licenses/MIT
