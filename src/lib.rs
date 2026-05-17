//! Authrs - Multi-tenant authentication service.

pub mod config;
pub mod db;
pub mod email;
pub mod error;
pub mod api;
pub mod domain;
pub mod openapi;
pub mod routes;
pub mod services;
pub mod repo;
pub mod middleware;
pub mod seed;

pub use config::Config;
pub use error::AppError;
pub use seed::{run as seed_run, SeedInput};
