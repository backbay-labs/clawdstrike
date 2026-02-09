#![allow(dead_code)]

use crate::{Blob, Bytes48, Cell, Error};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        Blob::from_hex(self.blob)
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    output: Option<(Vec<String>, Vec<String>)>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<(Vec<Cell>, Vec<Bytes48>)> {
        self.output.clone().map(|(cells, proofs)| {
            (
                cells
                    .iter()
                    .map(|s| Cell::from_hex(s).unwrap())
                    .collect::<Vec<Cell>>(),
                proofs
                    .iter()
                    .map(|s| Bytes48::from_hex(s).unwrap())
                    .collect::<Vec<Bytes48>>(),
            )
        })
    }
}
