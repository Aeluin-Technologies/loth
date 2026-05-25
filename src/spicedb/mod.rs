//! SpiceDB (Authzed API) integration.

pub mod client;
pub mod rebac;
pub mod schema;
pub mod pb {
    pub mod google {
        pub mod protobuf {
            include!("../generated/google.protobuf.rs");
        }
        pub mod rpc {
            include!("../generated/google.rpc.rs");
        }
    }

    pub mod authzed {
        pub mod api {
            pub mod v1 {
                include!("../generated/authzed.api.v1.rs");
            }
        }
    }
}
