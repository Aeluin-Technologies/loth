//! SpiceDB (Authzed API) integration.

pub mod client;
pub mod rebac;
pub mod schema;
pub mod pb {
    pub mod google {
        pub mod protobuf {
            include!(concat!(env!("OUT_DIR"), "/google.protobuf.rs"));
        }
        pub mod rpc {
            include!(concat!(env!("OUT_DIR"), "/google.rpc.rs"));
        }
    }

    pub mod authzed {
        pub mod api {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/authzed.api.v1.rs"));
            }
        }
    }
}
