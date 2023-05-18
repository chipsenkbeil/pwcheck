#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Checks the password against the specified username.
///
/// ### Linux
///
/// On Linux, this leverages PAM with the login service to perform authentication in a
/// non-interactive fashion via a username and password.
///
/// This method acts as a convenience to the `linux` module's implementation, and provides a service
/// of "login" for use with PAM.
///
/// ### MacOS
///
/// On MacOS, this leverages the `dscl` tool with `-authonly` to authenticate the user.
///
/// This method acts as a convenience to the `macos` module's implementation, and provides a
/// datasource of "." (local directory) and timeout of 0.5s to wait for a success or failure before
/// timing out.
///
/// ### Windows
///
/// On Windows platforms, this leverages the
/// [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
/// function to attempt to log a user on to the local computer.
///
/// Note that this function requires the running program to have the [SeTcbPrivilege
/// privilege][SeTcbPrivilege] set in order to log in as a user other than the user that started
/// the program. So it's safe to use this to validate the account of the user running this program,
/// but otherwise it needs a very high-level permission to validate the password, typically
/// something you'd see from running the program as an administrator.
///
/// This method acts as a convenience to the `windows` module's implementation.
///
/// [SeTcbPrivilege]: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system
pub fn pwcheck(username: &str, password: &str) -> PwcheckResult {
    #[cfg(target_os = "linux")]
    {
        const SERVICE: &str = "login";
        linux::pwcheck(username, password, SERVICE)
    }
    #[cfg(target_os = "macos")]
    {
        const DATASOURCE: &str = ".";
        const TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
        macos::pwcheck(username, password, DATASOURCE, TIMEOUT)
    }
    #[cfg(windows)]
    {
        windows::pwcheck(username, password)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        compile_error!("Only Linux, MacOS, and Windows are supported!");
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(doc_cfg, doc(cfg(target_os = "linux")))]
pub mod linux {
    use pam_client::conv_mock::Conversation;
    use pam_client::{Context, ErrorCode, Flag}; // Non-interactive implementation

    use super::PwcheckResult;

    /// For the Linux implementation of password checking, we're leveraging PAM to authenticate.
    /// This method accepts a third argument, `service`, which is the name of the service to use.
    /// In most cases, we want to use the "login" service.
    pub fn pwcheck(username: &str, password: &str, service: &str) -> PwcheckResult {
        let mut context = match Context::new(
            service,
            None,
            Conversation::with_credentials(username, password),
        ) {
            Ok(x) => x,
            Err(x) => return PwcheckResult::Err(Box::new(x)),
        };

        // Do not allow empty passwords, and suppress generated output
        let flags = Flag::DISALLOW_NULL_AUTHTOK & Flag::SILENT;

        // Authenticate the user
        match context.authenticate(flags) {
            Ok(_) => {}
            Err(x) if x.code() == ErrorCode::AUTH_ERR => return PwcheckResult::WrongPassword,
            Err(x) => return PwcheckResult::Err(Box::new(x)),
        }

        // Validate the account
        match context.acct_mgmt(flags) {
            Ok(_) => {}
            Err(x) if x.code() == ErrorCode::AUTH_ERR => return PwcheckResult::WrongPassword,
            Err(x) => return PwcheckResult::Err(Box::new(x)),
        }

        // Succeeded, so return ok
        PwcheckResult::Ok
    }
}

#[cfg(target_os = "macos")]
#[cfg_attr(doc_cfg, doc(cfg(target_os = "macos")))]
pub mod macos {
    use std::io::{self, Write};
    use std::thread;
    use std::time::{Duration, Instant};

    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    use super::PwcheckResult;

    const MACOS_HACK_SLEEP_DURATION: Duration = Duration::from_millis(20);
    const RECHECK_SLEEP_DURATION: Duration = Duration::from_millis(1);

    /// Converts `x` into a [`PwcheckResult`] of the `Err` variant that uses a [`std::io::Error`]
    /// to represent the error itself.
    macro_rules! make_err {
        ($x:expr) => {{
            PwcheckResult::Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                $x.to_string(),
            )))
        }};
    }

    /// Converts `x` (of type [`Result`]) into its underlying `Ok` variant. If `x` is the `Err`
    /// variant, it will instead be converted into a [`PwcheckResult`] and returned.
    macro_rules! unwrap_err {
        ($x:expr) => {{
            match $x {
                Ok(x) => x,
                Err(x) => return make_err!(x),
            }
        }};
    }

    /// For the MacOS implementation of password checking, we're leveraging the `dscl` tool.
    /// Because we need to spawn this tool within a tty to feed in a password prompt, a `timeout`
    /// is used to ensure that we do not continue waiting for success or failure indefinitely in
    /// the case that something has gone wrong feeding input.
    ///
    /// The `datasource` is used to specify the node name or host. You can read up on this more by
    /// doing `man dscl`. Providing "." as the datasource will use the local directory of the
    /// machine.
    pub fn pwcheck(
        username: &str,
        password: &str,
        datasource: &str,
        timeout: impl Into<Option<Duration>>,
    ) -> PwcheckResult {
        let pty_system = native_pty_system();
        let pair = unwrap_err!(pty_system.openpty(PtySize::default()));

        // Build and spawn our command in the form of `dscl . -authonly {username}`. This will
        // result in an interactive prompt for the password to authenticate the user.
        //
        // Note that supplying "." does validation on the local machine versus an active directory.
        let mut child = unwrap_err!(pair.slave.spawn_command({
            let mut cmd = CommandBuilder::new("dscl");
            cmd.args([datasource, "-authonly", username]);
            cmd
        }));

        // Release any handles owned by the slave: we don't need it now that we've spawned the
        // child
        drop(pair.slave);

        // Read the output in another thread. This is important because it is easy to encounter a
        // situation where read/write buffers fill and block either your process or the spawned
        // process.
        let reader = unwrap_err!(pair.master.try_clone_reader());
        thread::spawn(move || {
            // We block waiting for everything including EOF. If we don't do this, we fail
            // for some reason. We don't actually use the output, so swallow it.
            let _ = io::read_to_string(reader);
        });

        // Obtain the writer. When the writer is dropped, EOF will be sent to the program that was
        // spawned. It is important to take the writer even if you don't send anything to its stdin
        // so that EOF can be generated, otherwise you risk deadlocking yourself.
        let mut writer = unwrap_err!(pair.master.take_writer());

        // macOS quirk: the child and reader must be started and allowed a brief grace period
        // to run before we allow the writer to drop. Otherwise, the data we send to the kernel
        // to trigger EOF is interleaved with the data read by the reader! WTF!? This appears
        // to be a race condition for very short lived processes on macOS. I'd love to find a
        // more deterministic solution to this than sleeping.
        if cfg!(target_os = "macos") {
            thread::sleep(MACOS_HACK_SLEEP_DURATION);
        }

        // To avoid deadlock, wrt. reading and waiting, we send data to the stdin of the child in a
        // different thread.
        let msg = format!("{password}\r\n");
        thread::spawn(move || {
            // Continually try to send the password until we succeed. This is because we don't know
            // when su is ready to receive the password on the tty and we are unable to reliably
            // check for the prompt to be supplied.
            loop {
                if writer.write_all(msg.as_bytes()).is_err() {
                    break;
                }

                thread::sleep(RECHECK_SLEEP_DURATION * 10);
            }
        });

        // Keep track of when we started and how long to wait before timing out
        let start = Instant::now();
        let timeout = timeout.into();

        loop {
            // Check if our process has exited, and if so, handle success/failure
            match child.try_wait() {
                // Child has failed, so we assume wrong password
                Ok(Some(status)) => {
                    // Take care to drop the master after our processes are done, as some platforms
                    // get unhappy if it is dropped sooner than that.
                    drop(pair.master);

                    if status.success() {
                        return PwcheckResult::Ok;
                    } else {
                        return PwcheckResult::WrongPassword;
                    }
                }

                // Child is still running, so continue
                Ok(None) => {}

                // Unexpcted error occurred, so fail
                Err(x) => return PwcheckResult::Err(Box::new(x)),
            }

            // Check if we have exceeded the timeout, and fail accordingly
            if let Some(timeout) = timeout {
                if start.elapsed() > timeout {
                    // Terminate our process first to make sure we don't leave it hanging.
                    let kill_result = child.kill();

                    // Take care to drop the master after our processes are done, as some platforms
                    // get unhappy if it is dropped sooner than that.
                    drop(pair.master);

                    // If we failed to kill the process, return an error
                    unwrap_err!(kill_result);

                    // We assume that if the process hasn't completed, we supplied the wrong
                    // password and it never concluded.
                    //
                    // NOTE: I'd ideally like to make this a timeout error, but for some reason
                    // the process does not seem to exit normally, so I've converted this into a
                    // password failure report instead.
                    return PwcheckResult::Err(Box::new(io::Error::from(io::ErrorKind::TimedOut)));
                }
            }

            // Wait some period of time before rechecking so we don't spike the CPU
            thread::sleep(RECHECK_SLEEP_DURATION);
        }
    }
}

#[cfg(windows)]
#[cfg_attr(doc_cfg, doc(cfg(windows)))]
pub mod windows {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    };

    use super::PwcheckResult;

    /// For the windows implementation of password checking, we're leveraging the
    /// [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
    /// function to attempt to log a user on to the local computer.
    ///
    /// Note that this function requires the running program to have the [SeTcbPrivilege
    /// privilege][SeTcbPrivilege] set in order to log in as a user other than the user that
    /// started the program. So it's safe to use this to validate the account of the user running
    /// this program, but otherwise it needs a very high-level permission to validate the password,
    /// typically something you'd see from running the program as an administrator.
    ///
    /// [SeTcbPrivilege]: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system
    pub fn pwcheck(username: &str, password: &str) -> PwcheckResult {
        // Encode our username and password as utf16 for Windows and ensure we have a null
        // terminator character at the end of each.
        let username: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();
        let mut password: Vec<u16> = password.encode_utf16().chain(Some(0)).collect();

        // Attempt to invoke `LogonUserW` to validate the credentials. In the case of a
        // non-administrative account without the `SeTcbPrivilege` privilege being set, this can
        // only validate the current user's credentials, otherwise it fails because it lacks the
        // appropriate permission to invoke `LogonUserW`.
        let result = unsafe {
            let mut handle = HANDLE::default();

            // Attempt to logon as the `username` leveraging `password`.
            //
            // We provide a "." for the domain to validate the account by using only the local
            // account database.
            //
            // This logon type is intended for users who will be interactively using the computer,
            // such as a user being logged on by a terminal server, remote shell, or similar
            // process.
            //
            // Use the standard logon provider for the system. The default security provider is
            // negotiate, unless you pass NULL for the domain name and the user name is not in UPN
            // format. In this case, the default provider is NTLM.
            //
            // Returns a Foundation::BOOL of success.
            let result = LogonUserW(
                PCWSTR::from_raw(username.as_ptr()),
                PCWSTR::null(),
                PCWSTR::from_raw(password.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut handle,
            );

            // If we got a handle, we now want to close it because we were just checking for
            // success. The handle represents the specified user. You can use the returned handle
            // in calls to the `ImpersonateLoggedOnUser` function.
            if !handle.is_invalid() {
                CloseHandle(handle);
            }

            result.as_bool()
        };

        // Zero out the password for security.
        for p in password.iter_mut() {
            *p = 0;
        }

        if result {
            PwcheckResult::Ok
        } else {
            PwcheckResult::WrongPassword
        }
    }
}

/// Represents the result of checking a password. There are three potential outcomes:
///
/// * The check was a success and the password is correct for the user.
/// * The check was a failure and the password was incorrect for the user.
/// * The check failed unexpectedly and returned an error.
#[derive(Debug)]
pub enum PwcheckResult {
    /// Password is valid for specified user
    Ok,

    /// Password is invalid for specified user
    WrongPassword,

    /// Unexpected error occurred
    Err(Box<dyn std::error::Error>),
}

impl PwcheckResult {
    /// Returns true if this result is a success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns true if this result represents a wrong password.
    pub fn is_wrong_password(&self) -> bool {
        matches!(self, Self::WrongPassword)
    }

    /// Returns true if this result is an error.
    pub fn is_err(&self) -> bool {
        matches!(self, Self::Err(_))
    }

    /// Returns a reference to the error if this result is an error.
    pub fn as_err(&self) -> Option<&dyn std::error::Error> {
        match self {
            Self::Err(x) => Some(x.as_ref()),
            _ => None,
        }
    }

    /// Converts this result into a [`Result`]. The `WrongPassword` variant
    /// will get converted into a [`std::error::Error`].
    pub fn into_result(self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Ok => Ok(()),
            Self::WrongPassword => Err(Box::from("wrong password")),
            Self::Err(x) => Err(x),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_USERNAME: &str = std::env!("PWCHECK_TEST_USERNAME");
    static TEST_PASSWORD: &str = std::env!("PWCHECK_TEST_PASSWORD");

    #[test]
    fn should_return_ok_if_password_is_correct_for_the_user() {
        match pwcheck(TEST_USERNAME, TEST_PASSWORD) {
            PwcheckResult::Ok => {}
            PwcheckResult::WrongPassword => panic!("Failed with wrong password"),
            PwcheckResult::Err(x) => panic!("Failed unexpectedly: {x}"),
        }
    }

    #[test]
    fn should_return_wrong_password_if_password_is_incorrect_for_the_user() {
        match pwcheck(TEST_USERNAME, &format!("wrong{TEST_PASSWORD}wrong")) {
            PwcheckResult::WrongPassword => {}
            PwcheckResult::Ok => panic!("Succeeded unexpectedly with wrong password"),
            PwcheckResult::Err(x) => panic!("Failed unexpectedly: {x}"),
        }
    }
}
