fn main() {
    let proto_files = &["proto/handshake.proto", "proto/message.proto"];
    let proto_include = &["proto"];

    prost_build::compile_protos(proto_files, proto_include)
        .expect("Failed to compile protobuf definitions");
}
