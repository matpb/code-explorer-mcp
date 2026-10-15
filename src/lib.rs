//! Read-only MCP server over local shallow clones of GitHub and Bitbucket repos.

pub mod auth;
pub mod cli;
pub mod config;
pub mod git;
pub mod http;
pub mod keys;
pub mod logging;
pub mod metrics;
pub mod paths;
pub mod proc;
pub mod puller;
pub mod redact;
pub mod scan;
pub mod snapshot;
pub mod tools;
