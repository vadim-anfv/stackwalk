//! Stack with element ids. Replaces upstream data_structures.rs (rev ba96bc2bd7, CC0-1.0).
//! Every element carries an id: moving an element keeps it, every new or copied
//! element gets a fresh id from the shared generator.
use std::cell::Cell;
use std::rc::Rc;

use bitcoin::script::write_scriptint;

use super::{ExecError, read_scriptint};

/// Shared id generator (main stack and alt stack of one trace).
#[derive(Clone, Debug)]
pub struct IdGen(Rc<Cell<u64>>);

impl IdGen {
    pub fn new(start: u64) -> Self {
        IdGen(Rc::new(Cell::new(start)))
    }

    pub fn next(&self) -> u64 {
        let v = self.0.get();
        self.0.set(v + 1);
        v
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    pub data: Vec<u8>,
}

/// Returns minimally encoded scriptint as a byte vector.
pub fn scriptint_vec(n: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, n);
    buf[0..len].to_vec()
}

#[derive(Clone, Debug)]
pub struct Stack {
    items: Vec<Entry>,
    ids: IdGen,
}

impl PartialEq for Stack {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl Eq for Stack {}

impl Stack {
    pub fn new(ids: IdGen) -> Self {
        Self { items: Vec::new(), ids }
    }

    pub fn from_entries(items: Vec<Entry>, ids: IdGen) -> Self {
        Self { items, ids }
    }

    pub fn ids(&self) -> IdGen {
        self.ids.clone()
    }

    pub fn items(&self) -> &[Entry] {
        &self.items
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn last(&self) -> Result<Vec<u8>, ExecError> {
        self.topstr(-1)
    }

    pub fn top(&self, offset: isize) -> Result<&Entry, ExecError> {
        debug_assert!(offset < 0, "offsets should be < 0");
        self.items
            .len()
            .checked_sub(offset.unsigned_abs())
            .map(|i| &self.items[i])
            .ok_or(ExecError::InvalidStackOperation)
    }

    pub fn topstr(&self, offset: isize) -> Result<Vec<u8>, ExecError> {
        Ok(self.top(offset)?.data.clone())
    }

    pub fn topnum(&self, offset: isize, require_minimal: bool) -> Result<i64, ExecError> {
        read_scriptint(&self.top(offset)?.data, 4, require_minimal)
    }

    pub fn pushnum(&mut self, num: i64) {
        self.pushstr(&scriptint_vec(num));
    }

    pub fn pushstr(&mut self, v: &[u8]) {
        let id = self.ids.next();
        self.items.push(Entry { id, data: v.to_vec() });
    }

    /// Push an element that was moved (keeps its id).
    pub fn push(&mut self, v: Entry) {
        self.items.push(v);
    }

    /// Push a copy of an element (new id).
    pub fn push_copy(&mut self, v: &Entry) {
        self.pushstr(&v.data);
    }

    pub fn needn(&self, min_nb_items: usize) -> Result<(), ExecError> {
        if self.len() < min_nb_items { Err(ExecError::InvalidStackOperation) } else { Ok(()) }
    }

    pub fn popn(&mut self, n: usize) -> Result<(), ExecError> {
        for _ in 0..n {
            self.items.pop().ok_or(ExecError::InvalidStackOperation)?;
        }
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Entry> {
        self.items.pop()
    }

    pub fn popstr(&mut self) -> Result<Vec<u8>, ExecError> {
        Ok(self.items.pop().ok_or(ExecError::InvalidStackOperation)?.data)
    }

    pub fn popnum(&mut self, require_minimal: bool) -> Result<i64, ExecError> {
        let e = self.items.pop().ok_or(ExecError::InvalidStackOperation)?;
        read_scriptint(&e.data, 4, require_minimal)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn remove(&mut self, v: usize) -> Entry {
        self.items.remove(v)
    }

    pub fn as_v8_vec(&self) -> Vec<Vec<u8>> {
        self.items.iter().map(|e| e.data.clone()).collect()
    }
}
