use super::traits::OutputParser;
use super::nuclei::NucleiParser;
use std::collections::HashMap;

pub struct ParserRegistry {
    parsers: HashMap<String, Box<dyn OutputParser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        let mut parsers: HashMap<String, Box<dyn OutputParser>> = HashMap::new();
        
        let nuclei = NucleiParser;
        parsers.insert(nuclei.tool_name().to_string(), Box::new(nuclei));
        
        Self { parsers }
    }
    
    pub fn get_parser(&self, tool_name: &str) -> Option<&Box<dyn OutputParser>> {
        self.parsers.get(tool_name)
    }
}

