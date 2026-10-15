//! Serde helpers reading humantime strings ("30s", "5m") into `std::time::Duration`.

use std::time::Duration;

use serde::{Deserialize, Deserializer, de::Error};

fn parse<E: Error>(s: &str) -> Result<Duration, E> {
    humantime::parse_duration(s).map_err(|e| {
        E::custom(format!(
            "invalid duration {s:?}: {e}; use a form like \"30s\" or \"5m\""
        ))
    })
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse(&s)
}

pub mod option {
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => parse(&s).map(Some),
            None => Ok(None),
        }
    }
}
