#![allow(dead_code)]

use crate::Bytes48;
use crate::{Cell, Error};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    cell_indices: Vec<u64>,
    cells: Vec<String>,
}

impl Input {
    pub fn get_cell_indices(&self) -> Result<Vec<u64>, Error> {
        Ok(self.cell_indices.clone())
    }

    pub fn get_cells(&self) -> Result<Vec<Cell>, Error> {
        self.cells
            .iter()
            .map(|s| Cell::from_hex(s))
            .collect::<Result<Vec<Cell>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<(Vec<String>, Vec<String>)>,
}

impl Test {
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
