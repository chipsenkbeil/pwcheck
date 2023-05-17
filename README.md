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

## Install

```toml
[dependencies]
pwcheck = "0.1"
```

## Usage

```rust
use pwcheck::*;

fn main() {
    // Check if some username/password combo is valid
    match pwcheck("username", "password") {
        PwCheckResult::Ok => println!("Correct username & password!"),
        PwCheckResult::WrongPassword => println!("Incorrect username & password!"),
        PwCheckResult::Err(x) => println!("Encountered error: {x}"),
    }
}
```

## How It Works

### Unix

On Unix platforms, this leverages executing `su` to attempt to log into the user's account and
echo out a confirmation string. This requires that `su` be available, the underlying shell be
able to receive `-c` to execute a command, and `echo UNIQUE_CONFIRMATION` be a valid command.

For most platforms, this will result in using PAM to authenticate the user by their password,
which we feed in by running the `su` command in a tty and echoing the user's password into the
tty as if it was entered manually by a keyboard.

This method acts as a convenience around the `unix` module's implementation, and provides a
default timeout of 0.5s to wait for a success or failure before timing out.

### Windows

On Windows platforms, this leverages the
[LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
function to attempt to log a user on to the local computer.

Note that this function requires the running program to have the [SeTcbPrivilege
privilege][SeTcbPrivilege] set in order to log in as a user other than the user that started
the program. So it's safe to use this to validate the account of the user running this program,
but otherwise it needs a very high-level permission to validate the password, typically
something you'd see from running the program as an administrator.

[SeTcbPrivilege]: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system

## License

This project is licensed under either of

Apache License, Version 2.0, (LICENSE-APACHE or
[apache-license][apache-license]) MIT license (LICENSE-MIT or
[mit-license][mit-license]) at your option.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
[mit-license]: http://opensource.org/licenses/MIT
