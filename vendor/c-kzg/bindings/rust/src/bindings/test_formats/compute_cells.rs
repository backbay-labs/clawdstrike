#![allow(dead_code)]

use crate::{Blob, Cell, Error};
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
    output: Option<Vec<String>>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<Vec<Cell>> {
        self.output.clone().map(|cells| {
            cells
                .iter()
                .map(|s| Cell::from_hex(s).unwrap())
                .collect::<Vec<Cell>>()
        })
    }
}
