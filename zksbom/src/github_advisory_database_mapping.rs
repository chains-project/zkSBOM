use std::collections::HashMap;
use once_cell::sync::Lazy;

// Define a static HashMap that initializes once
pub static MAPPINGS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert("composer", "COMPOSER");
    map.insert("github", "GITHUB ACTIONS");
    map.insert("golang", "GO");   
    map.insert("maven", "MAVEN");
    map.insert("npm", "NPM");
    map.insert("nuget", "NUGET");
    map.insert("pypi", "PIP");
    map.insert("pub", "PUB");
    map.insert("gem", "RUBYGEMS");
    map.insert("cargo", "RUST");
    map.insert("swift", "SWIFT");
    map
});
