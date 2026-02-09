#![allow(dead_code)]

use crate::{Bytes48, Cell, Error};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    commitments: Vec<String>,
    cell_indices: Vec<u64>,
    cells: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_commitments(&self) -> Result<Vec<Bytes48>, Error> {
        self.commitments
            .iter()
            .map(|s| Bytes48::from_hex(s))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }

    pub fn get_cell_indices(&self) -> Result<Vec<u64>, Error> {
        Ok(self.cell_indices.clone())
    }

    pub fn get_cells(&self) -> Result<Vec<Cell>, Error> {
        self.cells
            .iter()
            .map(|s| Cell::from_hex(s))
            .collect::<Result<Vec<Cell>, Error>>()
    }

    pub fn get_proofs(&self) -> Result<Vec<Bytes48>, Error> {
        self.proofs
            .iter()
            .map(|s| Bytes48::from_hex(s))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<bool>,
}

impl Test {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
