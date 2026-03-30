pub fn get_github_ecosystem_name(purl: &str) -> Option<&'static str> {
    match purl {
        "composer" => Some("COMPOSER"),
        "github" => Some("GITHUB ACTIONS"),
        "golang" => Some("GO"),
        "maven" => Some("MAVEN"),
        "npm" => Some("NPM"),
        "nuget" => Some("NUGET"),
        "pypi" => Some("PIP"),
        "pub" => Some("PUB"),
        "gem" => Some("RUBYGEMS"),
        "cargo" => Some("RUST"),
        "swift" => Some("SWIFT"),
        _ => None,
    }
}
