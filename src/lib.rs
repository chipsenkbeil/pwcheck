#![doc = include_str!("../README.md")]

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Checks the password against the specified username.
///
/// ### Unix
///
/// On Unix platforms, this leverages executing `su` to attempt to log into the user's account and
/// echo out a confirmation string. This requires that `su` be available, the underlying shell be
/// able to receive `-c` to execute a command, and `echo UNIQUE_CONFIRMATION` be a valid command.
///
/// For most platforms, this will result in using PAM to authenticate the user by their password,
/// which we feed in by running the `su` command in a tty and echoing the user's password into the
/// tty as if it was entered manually by a keyboard.
///
/// This method acts as a convenience around the `unix` module's implementation, and provides a
/// default timeout of 0.5s to wait for a success or failure before timing out.
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
/// [SeTcbPrivilege]: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system
pub fn pwcheck(username: &str, password: &str) -> PwcheckResult {
    #[cfg(unix)]
    {
        const TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
        unix::pwcheck(username, password, TIMEOUT)
    }
    #[cfg(windows)]
    {
        windows::pwcheck(username, password)
    }
}

#[cfg(unix)]
pub mod unix {
    use std::io::{self, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    use super::PwcheckResult;

    /// Printed out by our call to echo. We want this to be unique so we can search for it in all
    /// of the stdout that su prints because it's not guaranteed that su will just print
    /// "Password:" as part of the prompt each time.
    const UNIQUE_CONFIRMATION: &str = "THEPASSWORDISOK";

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

    /// For the unix implementation of password checking, we're leveraging the `su` tool
    /// that is commonly available on Linux, MacOS, and the BSDs. Because we are doing a hack
    /// where we execute `su` and attempt to feed it a password over stdout, a `timeout`
    /// is used to ensure that we do not continue waiting for success or failure indefinitely
    /// in the case that something has gone wrong feeding input.
    ///
    /// Note that `timeout` is used both to wait for a process to terminate AND to wait to get
    /// output from a terminated process. This means that `pwcheck` could wait for up to twice the
    /// timeout if the process concludes exactly at `timeout`, but does not yield any output so we
    /// wait another `timeout` for the result.
    pub fn pwcheck(username: &str, password: &str, timeout: Duration) -> PwcheckResult {
        let pty_system = native_pty_system();
        let pair = unwrap_err!(pty_system.openpty(PtySize::default()));

        // Build and spawn our command in the form of `su -m {USERNAME} -c echo
        // {UNIQUE_CONFIRMATION}`, which will attempt to log in as the user via a password prompt
        // on the tty and then execute the command as it passes `-c echo {UNIQUE_CONFIRMATION}` to
        // the shell.
        //
        // We are assuming that all shells used have a `-c` flag and an echo command available
        // either on path or built into the shell itself.
        let mut child = unwrap_err!(pair.slave.spawn_command({
            let mut cmd = CommandBuilder::new("su");
            cmd.args(["-m", username, "-c"]);
            cmd.arg(&format!("echo {UNIQUE_CONFIRMATION}"));
            cmd
        }));

        // Release any handles owned by the slave: we don't need it now that we've spawned the
        // child
        drop(pair.slave);

        // Read the output in another thread. This is important because it is easy to encounter a
        // situation where read/write buffers fill and block either your process or the spawned
        // process.
        let (tx, rx) = mpsc::channel();
        let reader = unwrap_err!(pair.master.try_clone_reader());
        thread::spawn(move || {
            // We block waiting for everything including EOF, which means we should get both a
            // prompt like "Password:" and the output of our command.
            let out = io::read_to_string(reader).unwrap();

            // Send the output with newline characters, control characters, etc. removed.
            let out = out.replace(|c: char| c.is_whitespace() || c.is_control(), "");

            tx.send(out).unwrap();
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

        loop {
            // Check if our process has exited, and if so, handle success/failure
            match child.try_wait() {
                // Child has failed, so we assume wrong password
                Ok(Some(status)) => {
                    // Take care to drop the master after our processes are done, as some platforms
                    // get unhappy if it is dropped sooner than that.
                    drop(pair.master);

                    if !status.success() {
                        return PwcheckResult::WrongPassword;
                    }

                    // Child has succeeded, and we want to see if we got the confirmation back
                    let output = unwrap_err!(rx.recv_timeout(timeout));

                    if output.contains(UNIQUE_CONFIRMATION) {
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
                return PwcheckResult::WrongPassword;
            }

            // Wait some period of time before rechecking so we don't spike the CPU
            thread::sleep(RECHECK_SLEEP_DURATION);
        }
    }
}

#[cfg(windows)]
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
