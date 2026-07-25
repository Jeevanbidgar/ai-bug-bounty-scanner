//! Validated declarative adapter profiles for tools that share command-line patterns.
//!
//! Profiles deliberately cover only command construction and adapter metadata. They do not
//! bypass workflow validation, executable discovery, authorization, or the runtime security
//! boundary. Tools with richer semantics should continue to use specialized adapters.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetTransform {
    AsProvided,
    EnsureHttpUrl,
    EnsureHttpUrlWithSuffix(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlacement {
    Flag(&'static str),
    Positional,
    Stdin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPlacement {
    None,
    Flag {
        prelude: &'static [&'static str],
        flag: &'static str,
    },
    InlinePrefix(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandProfile {
    pub executable: &'static str,
    pub prefix_args: &'static [&'static str],
    pub target: TargetPlacement,
    pub target_transform: TargetTransform,
    pub suffix_args: &'static [&'static str],
    pub output: OutputPlacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterProfile {
    pub name: &'static str,
    pub tool_name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub risk_level: &'static str,
    pub requires_authorization: bool,
    pub timeout: u64,
    pub expected_outputs: &'static [&'static str],
    pub command: CommandProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCommand {
    pub argv: Vec<String>,
    pub stdin: Option<String>,
}

impl AdapterProfile {
    /// Validate the bundled profile before it is used as an execution preview contract.
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("name", self.name),
            ("tool_name", self.tool_name),
            ("description", self.description),
            ("category", self.category),
            ("risk_level", self.risk_level),
            ("executable", self.command.executable),
        ] {
            validate_static_value(field, value)?;
        }

        if !self.command.executable.eq_ignore_ascii_case(self.tool_name) {
            return Err(format!(
                "Adapter profile {} must execute its registered tool name",
                self.tool_name
            ));
        }
        if self.timeout == 0 {
            return Err(format!(
                "Adapter profile {} must define a non-zero timeout",
                self.tool_name
            ));
        }
        if self.expected_outputs.is_empty() {
            return Err(format!(
                "Adapter profile {} must describe its expected evidence",
                self.tool_name
            ));
        }

        match self.command.target {
            TargetPlacement::Flag(flag) => validate_flag("target flag", flag)?,
            TargetPlacement::Positional | TargetPlacement::Stdin => {}
        }
        match self.command.target_transform {
            TargetTransform::EnsureHttpUrlWithSuffix(suffix) if !suffix.starts_with('/') => {
                return Err(format!(
                    "Adapter profile {} URL suffix must begin with /",
                    self.tool_name
                ));
            }
            _ => {}
        }
        match self.command.output {
            OutputPlacement::None => {}
            OutputPlacement::Flag { prelude, flag } => {
                validate_flag("output flag", flag)?;
                validate_args("output prelude", prelude)?;
            }
            OutputPlacement::InlinePrefix(prefix) => validate_flag("output prefix", prefix)?,
        }

        validate_args("prefix arguments", self.command.prefix_args)?;
        validate_args("suffix arguments", self.command.suffix_args)?;
        validate_args("expected outputs", self.expected_outputs)?;
        Ok(())
    }

    /// Build a shell-free argument vector from the profile.
    pub fn build_command(
        &self,
        target: &str,
        output_file: Option<&str>,
    ) -> Result<ProfileCommand, String> {
        self.validate()?;
        let target = validate_runtime_value("Target", target)?;
        let target = transform_target(target, self.command.target_transform);

        let mut argv = Vec::with_capacity(
            1 + self.command.prefix_args.len() + self.command.suffix_args.len() + 4,
        );
        argv.push(self.command.executable.to_string());
        argv.extend(
            self.command
                .prefix_args
                .iter()
                .map(|arg| (*arg).to_string()),
        );

        let stdin = match self.command.target {
            TargetPlacement::Flag(flag) => {
                argv.push(flag.to_string());
                argv.push(target);
                None
            }
            TargetPlacement::Positional => {
                argv.push(target);
                None
            }
            TargetPlacement::Stdin => Some(target),
        };

        argv.extend(
            self.command
                .suffix_args
                .iter()
                .map(|arg| (*arg).to_string()),
        );

        if let Some(output_file) = output_file {
            let output_file = validate_runtime_value("Output path", output_file)?.to_string();
            match self.command.output {
                OutputPlacement::None => {
                    return Err(format!(
                        "Adapter profile {} does not accept an output path",
                        self.tool_name
                    ));
                }
                OutputPlacement::Flag { prelude, flag } => {
                    argv.extend(prelude.iter().map(|arg| (*arg).to_string()));
                    argv.push(flag.to_string());
                    argv.push(output_file);
                }
                OutputPlacement::InlinePrefix(prefix) => {
                    argv.push(format!("{}{}", prefix, output_file));
                }
            }
        }

        Ok(ProfileCommand { argv, stdin })
    }
}

fn validate_runtime_value<'a>(field: &str, value: &'a str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{} cannot be empty", field));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{} cannot contain control characters", field));
    }
    Ok(value)
}

fn validate_static_value(field: &str, value: &str) -> Result<(), String> {
    validate_runtime_value(field, value).map(|_| ())
}

fn validate_flag(field: &str, flag: &str) -> Result<(), String> {
    validate_static_value(field, flag)?;
    if !flag.starts_with('-') {
        return Err(format!("{} must begin with -", field));
    }
    Ok(())
}

fn validate_args(field: &str, values: &[&str]) -> Result<(), String> {
    for value in values {
        validate_static_value(field, value)?;
    }
    Ok(())
}

fn transform_target(target: &str, transform: TargetTransform) -> String {
    match transform {
        TargetTransform::AsProvided => target.to_string(),
        TargetTransform::EnsureHttpUrl => ensure_http_url(target),
        TargetTransform::EnsureHttpUrlWithSuffix(suffix) => {
            format!(
                "{}{}",
                ensure_http_url(target).trim_end_matches('/'),
                suffix
            )
        }
    }
}

fn ensure_http_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PROFILE: AdapterProfile = AdapterProfile {
        name: "Example",
        tool_name: "example",
        description: "Example profile",
        category: "test",
        risk_level: "low",
        requires_authorization: true,
        timeout: 30,
        expected_outputs: &["json"],
        command: CommandProfile {
            executable: "example",
            prefix_args: &["scan"],
            target: TargetPlacement::Flag("--url"),
            target_transform: TargetTransform::EnsureHttpUrlWithSuffix("/FUZZ"),
            suffix_args: &["--json"],
            output: OutputPlacement::Flag {
                prelude: &["--format", "json"],
                flag: "--output",
            },
        },
    };

    #[test]
    fn profile_builds_target_and_output_without_a_shell() {
        let command = TEST_PROFILE
            .build_command("example.com/", Some("/tmp/result.json"))
            .unwrap();

        assert_eq!(
            command.argv,
            vec![
                "example",
                "scan",
                "--url",
                "https://example.com/FUZZ",
                "--json",
                "--format",
                "json",
                "--output",
                "/tmp/result.json",
            ]
        );
        assert!(command.stdin.is_none());
    }

    #[test]
    fn profile_can_bind_a_target_to_standard_input() {
        let mut profile = TEST_PROFILE;
        profile.command.target = TargetPlacement::Stdin;
        profile.command.target_transform = TargetTransform::AsProvided;
        profile.command.output = OutputPlacement::None;

        let command = profile.build_command("example.com", None).unwrap();
        assert_eq!(command.argv, vec!["example", "scan", "--json"]);
        assert_eq!(command.stdin.as_deref(), Some("example.com"));
    }

    #[test]
    fn profile_rejects_control_characters() {
        let error = TEST_PROFILE
            .build_command("example.com\n--dangerous", None)
            .unwrap_err();
        assert!(error.contains("control characters"));
    }

    #[test]
    fn profile_rejects_invalid_static_flags() {
        let mut profile = TEST_PROFILE;
        profile.command.target = TargetPlacement::Flag("url");
        assert!(profile.validate().is_err());
    }
}
