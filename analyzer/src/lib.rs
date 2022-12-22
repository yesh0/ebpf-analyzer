//! An analyzer for eBPF binaries
//!
//! # Features
//!
//! This crate offers the following crate features:
//!
//! - `default`: `["atomic32", "atomic64"]`
//! - `atomic32`: Permits 32-bit atomic instructions.
//!   This feature will most likely get moved into an analyzer config option in the future.
//! - `atomic64`: Permits 64-bit atomic instructions. Same as above.
//! - `nightly`: This crate uses `mixed_integer_ops`, which is officially stable now.
//!   However, older rustc gets upset when we remove our `#[feature(mixed_integer_ops)]`.
//!   This features ensures that we retain that line of `#[feature(mixed_integer_ops)]`.
//!
//! # Usage
//!
//! The analyzer lies here at [analyzer::Analyzer], along with its config [analyzer::AnalyzerConfig].
//!
//! # Examples
//!
//! ```rust
//! use ebpf_analyzer::analyzer::Analyzer;
//! use ebpf_analyzer::analyzer::AnalyzerConfig;
//! let code = [
//!     // Returns without specifying a return value
//!     ebpf_consts::BPF_JMP_EXIT as u64,
//! ];
//! // Use the default AnalyzerConfig for testing purpose only
//! assert!(Analyzer::analyze(&code, &AnalyzerConfig::default()).is_err());
//! ```

#![no_std]
#![cfg_attr(feature = "nightly", feature(mixed_integer_ops))]
#![forbid(missing_docs)]

extern crate alloc;

pub mod analyzer;
pub mod blocks;
pub mod branch;
pub mod interpreter;
pub(crate) mod safe;
pub mod spec;
pub mod track;
