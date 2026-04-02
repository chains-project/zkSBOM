use zksbom::map_dependencies_vulnerabilities::{get_all_versions, get_vulnerable_versions};

mod create_inclusion_proof;

#[test]
fn test_get_versions_go() {
    let name = "github.com/opencontainers/runc";
    let result = get_all_versions(name, "go");
    let expected_to_be_included = vec![
        "v1.0.0-rc6",
        "v1.3.0",
        "v1.0.2",
        "v1.0.0-rc8",
        "v1.2.3",
        "v1.0.0-rc90",
        "v1.0.0-rc4",
        "v1.2.6",
        "v1.1.0-rc.1",
        "v1.0.0-rc7",
        "v1.2.7",
        "v1.0.0-rc93",
        "v1.0.0",
        "v1.2.8",
        "v0.0.1",
        "v1.3.3",
        "v1.1.6",
        "v1.4.0-rc.2",
        "v1.2.5",
        "v1.1.1",
        "v1.0.0-rc95",
        "v1.3.1",
        "v1.3.4",
        "v0.0.5",
        "v1.4.1",
        "v1.0.3",
        "v1.1.3",
        "v1.2.0-rc.3",
        "v1.0.0-rc94",
        "v1.1.2",
        "v1.1.11",
        "v1.3.0-rc.1",
        "v1.0.0-rc5",
        "v1.1.12",
        "v0.0.3",
        "v1.0.0-rc10",
        "v1.0.0-rc91",
        "v0.0.4",
        "v1.0.0-rc1",
        "v1.2.4",
        "v1.3.2",
        "v1.4.0-rc.1",
        "v1.2.1",
        "v1.3.0-rc.2",
        "v1.1.5",
        "v1.0.0-rc92",
        "v0.1.0",
        "v1.4.0",
        "v0.0.2",
        "v1.1.4",
        "v1.2.0",
        "v1.2.9",
        "v0.1.1",
        "v1.1.10",
        "v1.2.2",
        "v0.0.8",
        "v0.0.9",
        "v1.1.9",
        "v1.0.0-rc9",
        "v1.1.8",
        "v1.3.5",
        "v1.5.0-rc.1",
        "v1.2.0-rc.1",
        "v1.1.13",
        "v1.1.14",
        "v1.0.0-rc3",
        "v1.0.1",
        "v1.4.0-rc.3",
        "v1.1.0",
        "v1.0.0-rc2",
        "v1.1.7",
        "v0.0.6",
        "v0.0.7",
        "v1.2.0-rc.2",
        "v1.1.15",
    ];

    assert!(
        expected_to_be_included
            .iter()
            .all(|item| result.contains(&item.to_string())),
        "Not all required elements {:?} were found in {:?}",
        expected_to_be_included,
        result
    );
}

#[test]
fn test_get_versions_maven() {
    let name = "org.ops4j.pax.logging/pax-logging-log4j2";
    let result = get_all_versions(name, "maven");

    let expected_to_be_included = vec![
        "1.8.0", "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.9.0", "1.9.1",
        "1.9.2", "1.10.0", "1.10.1", "1.10.2", "1.10.3", "1.10.4", "1.10.5", "1.10.6", "1.10.7",
        "1.10.8", "1.10.9", "1.10.10", "1.11.0", "1.11.1", "1.11.2", "1.11.3", "1.11.4", "1.11.5",
        "1.11.6", "1.11.7", "1.11.8", "1.11.9", "1.11.10", "1.11.11", "1.11.12", "1.11.13",
        "1.11.14", "1.11.15", "1.11.16", "1.11.17", "1.12.0", "1.12.1", "1.12.2", "1.12.3",
        "1.12.4", "1.12.5", "1.12.6", "1.12.7", "1.12.8", "1.12.9", "1.12.10", "1.12.11",
        "1.12.12", "1.12.13", "1.12.14", "1.12.15", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4",
        "2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.0.9", "2.0.10", "2.0.11", "2.0.12", "2.0.13",
        "2.0.14", "2.0.15", "2.0.16", "2.0.17", "2.0.18", "2.0.19", "2.1.0", "2.1.1", "2.1.2",
        "2.1.3", "2.1.4", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7",
        "2.2.8", "2.2.9", "2.2.10", "2.2.11", "2.3.0", "2.3.1", "2.3.2",
    ];

    assert!(
        expected_to_be_included
            .iter()
            .all(|item| result.contains(&item.to_string())),
        "Not all required elements {:?} were found in {:?}",
        expected_to_be_included,
        result
    );
}

#[test]
fn test_get_versions_npm() {
    let name = "lodash.template";
    let result = get_all_versions(name, "npm");

    let expected_to_be_included = vec![
        "2.0.0", "2.1.0", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "3.0.0", "3.0.1", "3.1.0",
        "3.2.0", "3.3.0", "3.3.1", "3.3.2", "3.4.0", "3.5.0", "3.5.1", "3.6.0", "3.6.1", "3.6.2",
        "4.0.0", "4.0.1", "4.0.2", "4.1.0", "4.1.1", "4.18.0", "4.18.1", "4.2.0", "4.2.1", "4.2.2",
        "4.2.3", "4.2.4", "4.2.5", "4.3.0", "4.4.0", "4.5.0",
    ];

    assert!(
        expected_to_be_included
            .iter()
            .all(|item| result.contains(&item.to_string())),
        "Not all required elements {:?} were found in {:?}",
        expected_to_be_included,
        result
    );
}

#[test]
fn test_get_versions_rust() {
    let name = "sparse-merkle-tree";
    let result = get_all_versions(name, "rust");

    let expected_to_be_included = vec![
        "0.1.0-alpha1",
        "0.1.0-alpha2",
        "0.1.0-alpha3",
        "0.1.0",
        "0.1.1",
        "0.1.2",
        "0.1.3",
        "0.2.0",
        "0.3.0",
        "0.3.1-pre",
        "0.4.0-rc1",
        "0.5.0-rc1",
        "0.5.0-rc2",
        "0.5.2-rc1",
        "0.5.2",
        "0.5.3",
        "0.5.4",
        "0.6.0",
        "0.6.1",
    ];

    assert!(
        expected_to_be_included
            .iter()
            .all(|item| result.contains(&item.to_string())),
        "Not all required elements {:?} were found in {:?}",
        expected_to_be_included,
        result
    );
}

#[test]
fn test_vulnerable_range_less_than() {
    let all_versions = vec![
        "1.0.0".to_string(),
        "2.0.0".to_string(),
        "5.0.1".to_string(),
    ];
    let range = "< 5.0.1";

    let result = get_vulnerable_versions(all_versions, range);

    assert_eq!(result, vec!["1.0.0", "2.0.0"]);
}

#[test]
fn test_compound_range() {
    let all_versions = vec![
        "0.9.0".to_string(),
        "0.10.2".to_string(),
        "0.10.5".to_string(),
        "0.11.0".to_string(),
    ];
    let range = ">= 0.10.0, < 0.10.5";

    let result = get_vulnerable_versions(all_versions, range);

    assert_eq!(result, vec!["0.10.2"]);
}

#[test]
fn test_pre_release_versions() {
    let all_versions = vec![
        "1.0.0-beta.25".to_string(),
        "1.0.0".to_string(),
        "2.0.0".to_string(),
    ];
    let range = "< 1.0.0";

    let result = get_vulnerable_versions(all_versions, range);

    // This will include the beta version because 1.0.0-beta.25 < 1.0.0
    assert_eq!(result, vec!["1.0.0-beta.25"]);
}
