# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.2.0 (May 17, 2023)

This release splits out Linux and MacOS support and how they are implemented.

From a high level, `MacOS` now uses `dscl` instead of `su` to authenticate and
`Linux` now uses `PAM` with the `login` service to authenticate.

### Added

- `pwcheck::linux` module with `pwcheck::linux::Method` and
  `pwcheck::linux::pwcheck` method that leverages the method.
- `pwcheck::macos` module with `pwcheck::macos::Method` and
  `pwcheck::macos::pwcheck` method that leverages the method.
- `pwcheck::windows::Method` for use with revised `pwcheck::windows::pwcheck`
  method that leverages the method.

### Changed

- `pwcheck::windows::pwchec` now takes `pwcheck::windows::Method`.

### Removed

- `pwcheck::unix` module has been removed.

# 0.1.0 (May 17, 2023)

This is the first release of the project.

### Added

- `pwcheck::pwcheck` function that provides the default experience for
  validating a password for a specified user on Linux, MacOS, and Windows
- `pwcheck::PwcheckResult` enum to distinguish a successful comparison, an
  invalid comparison, and an unexpected error that occurred.
- `pwcheck::unix::pwcheck` function that provides the Unix-specific
  implementation used on Linux and MacOS. This function spawns
  `su -m {USERNAME} -c echo THEPASSWORDISOK` within a tty to validate
  the password.
- `pwcheck::windows::pwcheck` function that provides the Windows-specific
  implementation. This function takes the usual `username` and `password`
  parameters and invokes `LogonUserW` underneath.
