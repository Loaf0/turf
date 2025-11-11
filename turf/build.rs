use std::env;

fn main() {
    if let Ok(path) = env::var("NPCAP_LIB") {
        println!("cargo:rustc-link-search=native={}", path);
    } else {
        println!("cargo:warning=NPCAP_LIB not set; using default Npcap path");
        println!("cargo:rustc-link-search=native=G:/Coding Projects/Rust/libs/npcapsdk/x64");
    }

    println!("cargo:rustc-link-lib=Packet");
    println!("cargo:rustc-link-lib=wpcap");
    println!("cargo:rustc-link-search=native=src");

}