use std::path::{Path, PathBuf};

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
    println!("cargo:rerun-if-changed=cpp/verify_wrapper.h");
    println!("cargo:rerun-if-changed=cpp/verify_wrapper.cpp");

    // Determine vcpkg triplet and GSL include path (from vcpkg)
    let vcpkg_triplet = detect_vcpkg_triplet(&ozks_root);

    let gsl_include_path =
        ozks_include_path.join(format!("build/vcpkg_installed/{}/include", vcpkg_triplet));

    // Compile the C++ verification wrapper
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

    cpp_build
        .include(ozks_include_path)
        .include(ozks_include_path.join("oZKS"))
        .include(ozks_include_path.join("build"))
        .include(&gsl_include_path)
        .file("cpp/verify_wrapper.cpp")
        .compile("ozks_verify_wrapper");

    // Link the oZKS core library
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

    // On Windows, oZKS bundles blake2b (via FourQ) which conflicts with the blake2b-rs crate.
    // Allow the linker to deduplicate these identical symbols.
    // Also suppress auto-linked PocoFoundation.lib from Poco headers (#pragma comment(lib))
    // since the actual library name depends on the vcpkg triplet (e.g. PocoFoundationmd.lib).
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-arg=/FORCE:MULTIPLE");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:PocoFoundation.lib");
    }

    // Link C++ standard library
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else if !cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=stdc++");
    }
    // Windows: MSVC C++ standard library is linked automatically

    // Generate FFI bindings from the C wrapper header
    let bindings = bindgen::Builder::default()
        .header("cpp/verify_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("ozks_verify_proof")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
