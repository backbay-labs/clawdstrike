//! Iterate over available registers.

use crate::{MachineEnv, PReg, RegClass};

/// Keep track of where we are in the register traversal.
struct Cursor<'a> {
    registers: &'a [PReg],
    index: usize,
    offset: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn new(registers: &'a [PReg], offset_hint: usize) -> Self {
        let offset = if registers.len() > 0 {
            offset_hint % registers.len()
        } else {
            0
        };
        Self {
            registers,
            index: 0,
            offset,
        }
    }

    /// Wrap around the end of the register list; [`Cursor::done`] guarantees we
    /// do not see the same register twice.
    #[inline]
    fn wrap(index: usize, end: usize) -> usize {
        if index >= end {
            index - end
        } else {
            index
        }
    }

    /// Advance to the next register and return it.
    #[inline]
    fn advance(&mut self) -> PReg {
        let loc = Self::wrap(self.index + self.offset, self.registers.len());
        let reg = self.registers[loc];
        self.index += 1;
        reg
    }

    /// Return `true` if we have seen all registers.
    #[inline]
    fn done(&self) -> bool {
        self.index >= self.registers.len()
    }
}

/// This iterator represents a traversal through all allocatable registers of a
/// given class, in a certain order designed to minimize allocation contention.
///
/// The order in which we try registers is somewhat complex:
/// - First, if the register is fixed (i.e., pre-assigned), return that and stop
///   iteration.
/// - Then, if there is a hint, try that one.
/// - Next we try registers in a traversal order that is based on an "offset"
///   (usually the bundle index) spreading pressure evenly among registers to
///   reduce commitment-map contention.
/// - Within that scan, we try registers in two groups: first, preferred
///   registers; then, non-preferred registers. (In normal usage, these consist
///   of caller-save and callee-save registers respectively, to minimize
///   clobber-saves; but they need not.)
pub struct RegTraversalIter<'a> {
    is_fixed: bool,
    fixed: Option<PReg>,
    use_hint: bool,
    hint: Option<PReg>,
    preferred: Cursor<'a>,
    non_preferred: Cursor<'a>,
    limit: Option<usize>,
}

impl<'a> RegTraversalIter<'a> {
    pub fn new(
        env: &'a MachineEnv,
        class: RegClass,
        fixed: Option<PReg>,
        hint: Option<PReg>,
        offset: usize,
        limit: Option<usize>,
    ) -> Self {
        debug_assert!(fixed != Some(PReg::invalid()));
        debug_assert!(hint != Some(PReg::invalid()));

        let class = class as u8 as usize;
        let preferred = Cursor::new(&env.preferred_regs_by_class[class], offset);
        let non_preferred = Cursor::new(&env.non_preferred_regs_by_class[class], offset);

        Self {
            is_fixed: fixed.is_some(),
            fixed,
            use_hint: hint.is_some(),
            hint,
            preferred,
            non_preferred,
            limit,
        }
    }
}

impl<'a> core::iter::Iterator for RegTraversalIter<'a> {
    type Item = PReg;

    fn next(&mut self) -> Option<PReg> {
        if self.is_fixed {
            return self.fixed.take();
        }

        if self.use_hint {
            self.use_hint = false;
            if self.hint.unwrap().hw_enc() < self.limit.unwrap_or(usize::MAX) {
                return self.hint;
            }
        }

        while !self.preferred.done() {
            let reg = self.preferred.advance();
            if Some(reg) == self.hint || reg.hw_enc() >= self.limit.unwrap_or(usize::MAX) {
                continue; // Try again; we already tried the hint or we are outside of the register range limit.
            }
            return Some(reg);
        }

        while !self.non_preferred.done() {
            let reg = self.non_preferred.advance();
            if Some(reg) == self.hint || reg.hw_enc() >= self.limit.unwrap_or(usize::MAX) {
                continue; // Try again; we already tried the hint or we are outside of the register range limit.
            }
            return Some(reg);
        }

        None
    }
}
