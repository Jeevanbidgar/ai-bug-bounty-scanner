use super::dalfox::DalfoxParser;
use super::nikto::NiktoParser;
use super::nuclei::NucleiParser;
use super::traits::OutputParser;
use super::wpscan::WpScanParser;
use std::collections::HashMap;

pub struct ParserRegistry {
    parsers: HashMap<String, Box<dyn OutputParser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        let mut parsers: HashMap<String, Box<dyn OutputParser>> = HashMap::new();

        let nuclei = NucleiParser;
        parsers.insert(nuclei.tool_name().to_string(), Box::new(nuclei));

        let nikto = NiktoParser;
        parsers.insert(nikto.tool_name().to_string(), Box::new(nikto));

        let wpscan = WpScanParser;
        parsers.insert(wpscan.tool_name().to_string(), Box::new(wpscan));

        let dalfox = DalfoxParser;
        parsers.insert(dalfox.tool_name().to_string(), Box::new(dalfox));

        Self { parsers }
    }

    pub fn get_parser(&self, tool_name: &str) -> Option<&dyn OutputParser> {
        self.parsers.get(tool_name).map(Box::as_ref)
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_every_structured_output_parser() {
        let registry = ParserRegistry::new();

        for tool in ["nuclei", "nikto", "wpscan", "dalfox"] {
            assert!(registry.get_parser(tool).is_some(), "missing {tool} parser");
        }
    }
}
