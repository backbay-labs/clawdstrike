//! Auth-related route helpers that pair with `middleware/auth.rs`.
//!
//! Today the auth middleware lives alongside this file's siblings under
//! `api_server::middleware::auth`. This module is reserved for any
//! token-related routes that aren't strictly middleware (currently empty
//! — `rotate_local_api_token_route` lives in `token_rotation.rs`).
