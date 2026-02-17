use std::path::{Path, PathBuf};

/// Find the sqlite3.h include path from the libsqlite3-sys crate source.
fn find_sqlite3_include() -> Option<PathBuf> {
    // Check DEP_SQLITE3_INCLUDE first (set if libsqlite3-sys is a direct dep that emits it)
    if let Ok(include) = std::env::var("DEP_SQLITE3_INCLUDE") {
        return Some(PathBuf::from(include));
    }

    // Find sqlite3.h from libsqlite3-sys source in the cargo registry
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").unwrap_or_default()
        } else {
            std::env::var("HOME").unwrap_or_default()
        };
        format!("{}/.cargo", home)
    });

    let registry_src = PathBuf::from(&cargo_home).join("registry").join("src");
    if let Ok(indices) = std::fs::read_dir(&registry_src) {
        for index in indices.flatten() {
            if let Ok(crates) = std::fs::read_dir(index.path()) {
                for krate in crates.flatten() {
                    if let Some(name) = krate.file_name().to_str() {
                        if name.starts_with("libsqlite3-sys-") {
                            let sqlite3_dir = krate.path().join("sqlite3");
                            if sqlite3_dir.join("sqlite3.h").exists() {
                                return Some(sqlite3_dir);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Auto-detect the vcpkg triplet by checking what's actually installed.
/// Supports override via the VCPKG_DEFAULT_TRIPLET environment variable.
fn detect_vcpkg_triplet(ozks_root: &Path) -> String {
    // Allow explicit override
    if let Ok(triplet) = std::env::var("VCPKG_DEFAULT_TRIPLET") {
        return triplet;
    }

    let vcpkg_installed = ozks_root.join("build/vcpkg_installed");

    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["arm64-osx", "x64-osx"]
    } else if cfg!(target_os = "windows") {
        &["x64-windows-static-md", "x64-windows-static", "x64-windows"]
    } else {
        &["x64-linux"]
    };

    for candidate in candidates {
        if vcpkg_installed.join(candidate).join("include").exists() {
            return candidate.to_string();
        }
    }

    candidates[0].to_string()
}

fn main() {
    // Set up library paths - point to third_party/oZKS
    let ozks_root = PathBuf::from("third_party/oZKS");
    let ozks_lib_path = ozks_root.join("build/lib");
    let ozks_include_path = &ozks_root;
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Tell cargo to recompile if wrapper files change
    println!("cargo:rerun-if-changed=cpp/wrapper/cpp_wrapper.h");
    println!("cargo:rerun-if-changed=cpp/wrapper/cpp_wrapper.cpp");
    println!("cargo:rerun-if-changed=cpp/storage/sqlite/file_storage_sqlite.h");
    println!("cargo:rerun-if-changed=cpp/storage/sqlite/file_storage_sqlite.cpp");

    // Determine vcpkg triplet and GSL include path (from vcpkg)
    let vcpkg_triplet = detect_vcpkg_triplet(&ozks_root);

    let gsl_include_path =
        ozks_include_path.join(format!("build/vcpkg_installed/{}/include", vcpkg_triplet));

    // Compile the C++ wrapper and SQLite storage backend
    let mut cpp_build = cc::Build::new();
    cpp_build.cpp(true);

    // Set C++ standard and platform-specific flags
    if cfg!(target_env = "msvc") {
        cpp_build.flag("/std:c++17").flag("/EHsc");
    } else {
        cpp_build
            .flag("-std=c++17")
            .flag("-fPIC")
            .flag("-Wno-unused-parameter");
    }

    // When using a static vcpkg triplet, define POCO_STATIC so Poco headers
    // don't use __declspec(dllimport) on symbols we're linking statically.
    if vcpkg_triplet.contains("static") {
        cpp_build.define("POCO_STATIC", None);
    }

    // Add sqlite3.h include path from libsqlite3-sys (bundled)
    if let Some(sqlite3_include) = find_sqlite3_include() {
        cpp_build.include(&sqlite3_include);
    }

    cpp_build
        .include(ozks_include_path)
        .include(ozks_include_path.join("oZKS"))
        .include(ozks_include_path.join("examples/ozks_simple"))
        .include(ozks_include_path.join("build"))
        .include(&gsl_include_path)
        .include("cpp/wrapper")
        .include("cpp/storage/sqlite")
        .file("cpp/wrapper/cpp_wrapper.cpp")
        .file("cpp/storage/sqlite/file_storage_sqlite.cpp")
        .compile("ozks_wrapper");

    // Link the oZKS libraries
    // On MSVC, cmake puts libs in Debug/ or Release/ subdirectories
    let ozks_link_path = if cfg!(target_env = "msvc") {
        let release_path = ozks_lib_path.join("Release");
        let debug_path = ozks_lib_path.join("Debug");
        if release_path.join("ozks-1.6.lib").exists() {
            release_path
        } else if debug_path.join("ozks-1.6.lib").exists() {
            debug_path
        } else {
            ozks_lib_path.clone()
        }
    } else {
        ozks_lib_path.clone()
    };

    if ozks_link_path.exists() {
        println!(
            "cargo:rustc-link-search=native={}",
            ozks_link_path.display()
        );
        println!("cargo:rustc-link-lib=static=ozks-1.6");
        println!("cargo:rustc-link-lib=static=ozks-simple");
    } else {
        eprintln!(
            "Warning: oZKS libraries not found at {}",
            ozks_link_path.display()
        );
    }

    // Link against vcpkg libraries (Poco, OpenSSL)
    let vcpkg_lib_path =
        ozks_include_path.join(format!("build/vcpkg_installed/{}/lib", vcpkg_triplet));

    if vcpkg_lib_path.exists() {
        println!(
            "cargo:rustc-link-search=native={}",
            vcpkg_lib_path.display()
        );
        // Poco library name varies by vcpkg triplet
        if vcpkg_triplet == "x64-windows-static-md" {
            println!("cargo:rustc-link-lib=static=PocoFoundationmd");
        } else if vcpkg_triplet == "x64-windows-static" {
            println!("cargo:rustc-link-lib=static=PocoFoundationmt");
        } else {
            println!("cargo:rustc-link-lib=static=PocoFoundation");
        }

        // On Windows with static linking, OpenSSL libraries may have different names
        if cfg!(target_os = "windows") {
            println!("cargo:rustc-link-lib=static=libssl");
            println!("cargo:rustc-link-lib=static=libcrypto");
        } else {
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
        }
    }

    // Link SQLite3 (bundled by rusqlite)
    println!("cargo:rustc-link-lib=static=sqlite3");

    // On Windows, oZKS bundles blake2b (via FourQ) which conflicts with the blake2b-rs crate.
    // Allow the linker to deduplicate these identical symbols.
    // Also suppress auto-linked PocoFoundation.lib from Poco headers (#pragma comment(lib))
    // since the actual library name depends on the vcpkg triplet (e.g. PocoFoundationmd.lib).
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-arg=/FORCE:MULTIPLE");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:PocoFoundation.lib");
    }

    // Generate FFI bindings from the C wrapper header
    let bindings = bindgen::Builder::default()
        .header("cpp/wrapper/cpp_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("ozks_.*")
        .allowlist_type("OZKSHandle|TrieId")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
