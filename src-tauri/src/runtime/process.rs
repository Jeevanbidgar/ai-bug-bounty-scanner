/// Apply Windows-specific child process options to prevent console windows
/// from flashing when launched from the desktop app.
///
/// On non-Windows platforms this is a no-op.
pub fn configure_tokio_command(cmd: &mut tokio::process::Command) {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }

    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
}

/// Create a Tokio command pre-configured with platform-specific process flags.
pub fn hidden_tokio_command<S: AsRef<std::ffi::OsStr>>(program: S) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    configure_tokio_command(&mut cmd);
    cmd
}

/// Apply Windows-specific child process options to prevent console windows
/// from flashing when launched from the desktop app.
///
/// On non-Windows platforms this is a no-op.
pub fn configure_std_command(cmd: &mut std::process::Command) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
}

/// Create a std command pre-configured with platform-specific process flags.
pub fn hidden_std_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    configure_std_command(&mut cmd);
    cmd
}
