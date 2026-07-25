use std::collections::HashMap;
use std::net::IpAddr;

/// Validate a concrete scan target before it reaches any external tool.
///
/// Workflow targets must be a hostname, IP address, CIDR range, or an HTTP(S)
/// URL. Shells are never involved, but rejecting option-like and whitespace-
/// containing values also prevents tools from treating a target as a flag.
pub fn validate_scan_target(raw_target: &str) -> Result<String, String> {
    let target = raw_target.trim();

    if target.is_empty() {
        return Err("A non-empty target is required".to_string());
    }
    if target.len() > 2048 {
        return Err("Target is too long (maximum 2048 characters)".to_string());
    }
    if target.starts_with('-') {
        return Err("Target cannot start with '-'".to_string());
    }
    if target
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("Target cannot contain whitespace or control characters".to_string());
    }

    if let Some((scheme, remainder)) = target.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err("Only http:// and https:// target URLs are supported".to_string());
        }

        let authority = remainder
            .split(['/', '?', '#'])
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Target URL must include a hostname or IP address".to_string())?;
        if authority.contains('@') {
            return Err("Target URLs cannot contain embedded credentials".to_string());
        }

        validate_authority(authority)?;
        return Ok(target.to_string());
    }

    if target.contains('/') {
        validate_cidr(target)?;
        return Ok(target.to_string());
    }

    if target.parse::<IpAddr>().is_ok() {
        return Ok(target.to_string());
    }

    validate_hostname(target)?;
    Ok(target.to_string())
}

pub fn workflow_target_inputs(validated_target: &str) -> Result<HashMap<String, String>, String> {
    let target = validate_scan_target(validated_target)?;
    let mut inputs = HashMap::new();
    inputs.insert("target".to_string(), target.clone());

    if let Some((scheme, remainder)) = target.split_once("://") {
        let authority = remainder
            .split(['/', '?', '#'])
            .next()
            .ok_or_else(|| "Target URL is missing an authority".to_string())?;
        let host = authority_host(authority)?;
        inputs.insert("host".to_string(), host.clone());
        if host.parse::<IpAddr>().is_err() {
            inputs.insert("domain".to_string(), host);
        }
        inputs.insert(
            "url".to_string(),
            format!("{}://{}", scheme.to_ascii_lowercase(), authority),
        );
        inputs.insert("target_kind".to_string(), "url".to_string());
    } else if target.contains('/') {
        inputs.insert("host".to_string(), target.clone());
        inputs.insert("target_kind".to_string(), "cidr".to_string());
    } else {
        inputs.insert("host".to_string(), target.clone());
        if target.parse::<IpAddr>().is_err() {
            inputs.insert("domain".to_string(), target.clone());
        }
        let url_host = if target.parse::<IpAddr>().is_ok() && target.contains(':') {
            format!("[{}]", target)
        } else {
            target.clone()
        };
        inputs.insert("url".to_string(), format!("https://{}", url_host));
        inputs.insert("target_kind".to_string(), "host".to_string());
    }

    Ok(inputs)
}

fn authority_host(authority: &str) -> Result<String, String> {
    if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .ok_or_else(|| "IPv6 target URL is missing a closing bracket".to_string())?;
        return Ok(authority[1..closing].to_string());
    }
    Ok(authority
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':'))
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .to_string())
}

fn validate_authority(authority: &str) -> Result<(), String> {
    if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .ok_or_else(|| "IPv6 target URL is missing a closing bracket".to_string())?;
        authority[1..closing]
            .parse::<IpAddr>()
            .map_err(|_| "Target URL contains an invalid IPv6 address".to_string())?;

        let suffix = &authority[closing + 1..];
        if !suffix.is_empty() {
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| "Target URL authority is invalid".to_string())?;
            validate_port(port)?;
        }
        return Ok(());
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (authority, None),
    };

    if let Some(port) = port {
        validate_port(port)?;
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    validate_hostname(host)
}

fn validate_port(port: &str) -> Result<(), String> {
    let parsed = port
        .parse::<u16>()
        .map_err(|_| "Target URL contains an invalid port".to_string())?;
    if parsed == 0 {
        return Err("Target URL port must be between 1 and 65535".to_string());
    }
    Ok(())
}

fn validate_cidr(target: &str) -> Result<(), String> {
    let (address, prefix) = target
        .split_once('/')
        .ok_or_else(|| "CIDR target must contain a prefix length".to_string())?;
    if prefix.contains('/') {
        return Err("CIDR target is invalid".to_string());
    }

    let address = address
        .parse::<IpAddr>()
        .map_err(|_| "Target paths require an http:// or https:// URL".to_string())?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "CIDR prefix length is invalid".to_string())?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(format!("CIDR prefix must be between 0 and {}", maximum));
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<(), String> {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty() || hostname.len() > 253 {
        return Err("Target hostname is invalid".to_string());
    }
    if hostname.starts_with("*.") {
        return Err(
            "Run targets must be concrete; wildcard scopes are not executable targets".to_string(),
        );
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Target hostname contains an invalid label".to_string());
        }
        let bytes = label.as_bytes();
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(
                "Target hostname may contain only letters, digits, dots, and hyphens".to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_scan_target, workflow_target_inputs};

    #[test]
    fn accepts_supported_target_forms() {
        for target in [
            "example.com",
            "sub-domain.example.com.",
            "127.0.0.1",
            "192.0.2.0/24",
            "2001:db8::1",
            "2001:db8::/32",
            "https://example.com:8443/api?mode=test",
            "http://[2001:db8::1]:8080/",
        ] {
            assert_eq!(validate_scan_target(target).unwrap(), target);
        }
    }

    #[test]
    fn rejects_option_injection_and_ambiguous_targets() {
        for target in [
            "-iL",
            "example.com --script vuln",
            "ftp://example.com",
            "https://user:pass@example.com",
            "*.example.com",
            "example.com/path",
            "https://example.com:0",
            "192.0.2.0/64",
        ] {
            assert!(validate_scan_target(target).is_err(), "accepted {target}");
        }
    }

    #[test]
    fn derives_tool_specific_target_forms() {
        let url = workflow_target_inputs("https://example.com:8443/path?q=1").unwrap();
        assert_eq!(url["domain"], "example.com");
        assert_eq!(url["host"], "example.com");
        assert_eq!(url["url"], "https://example.com:8443");

        let host = workflow_target_inputs("example.com").unwrap();
        assert_eq!(host["url"], "https://example.com");

        let cidr = workflow_target_inputs("192.0.2.0/24").unwrap();
        assert!(!cidr.contains_key("url"));

        let ip = workflow_target_inputs("192.0.2.10").unwrap();
        assert!(!ip.contains_key("domain"));
    }
}
