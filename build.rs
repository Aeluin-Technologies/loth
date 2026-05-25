//! Build script compiling vendored Authzed API v1 protos.

fn main() {
    /*let out_dir = "src/generated";
    let _ = std::fs::create_dir(out_dir);

    let protos = &[
        "./proto/authzed/api/v1/permission_service.proto",
        "./proto/authzed/api/v1/schema_service.proto",
        "./proto/authzed/api/v1/watch_service.proto",
    ];

    let mut prost_config = prost_build::Config::new();
    prost_config.compile_well_known_types();

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir(out_dir)
        .compile_with_config(prost_config, protos, &["./proto"])
        .unwrap();*/

    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=src/generated");
}
