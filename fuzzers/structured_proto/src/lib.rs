//! Structured mailbox input + mutators (design note #803/#865). `catalog` loads the librarian JSON at runtime.
pub mod catalog;
pub mod mailbox;
use std::{borrow::Cow, num::NonZeroUsize};

use libafl::{
    Error,
    generators::Generator,
    inputs::{Input, ListInput},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};
use serde::{Deserialize, Serialize};

/// Length field: derived from the buffer by default, deliberately wrong only when mutated so.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum LenSpec {
    #[default]
    Derived,
    Override(u32),
    Delta(i32),
}

impl LenSpec {
    pub fn resolve(&self, buf_len: usize) -> u32 {
        match self {
            LenSpec::Derived => buf_len as u32,
            LenSpec::Override(v) => *v,
            LenSpec::Delta(d) => (buf_len as u32).wrapping_add_signed(*d),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Msg {
    pub cmd: u8,
    pub args: Vec<u32>,
    pub buf: Vec<u8>,
    pub len: LenSpec,
}
impl Input for Msg {}

pub type Session = ListInput<Msg>;

/// Interesting u32 values (extend with SRAM/flash window bounds from the catalog).
pub const POOL: &[u32] = &[0, 1, u32::MAX, 0x7fff_ffff, 0x8000_0000, 0xff, 0x100, 0xffff, 0x1_0000];

fn pick<S: HasRand>(state: &mut S, n: usize) -> usize {
    state.rand_mut().below(NonZeroUsize::new(n).unwrap())
}

/// Replace one arg of one message by a pool value.
pub struct PoolArgMutator;
impl<S: HasRand> Mutator<Session, S> for PoolArgMutator {
    fn mutate(&mut self, state: &mut S, input: &mut Session) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = pick(state, n);
        let m = &mut input.parts_mut()[mi];
        if m.args.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let ai = pick(state, m.args.len());
        m.args[ai] = POOL[pick(state, POOL.len())];
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<libafl::corpus::CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
impl Named for PoolArgMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PoolArgMutator")
    }
}

/// Deliberately wrong length (the knob; schedule it with low weight).
pub struct LenLieMutator;
impl<S: HasRand> Mutator<Session, S> for LenLieMutator {
    fn mutate(&mut self, state: &mut S, input: &mut Session) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = pick(state, n);
        let spec = if pick(state, 2) == 0 {
            LenSpec::Override(POOL[pick(state, POOL.len())])
        } else {
            LenSpec::Delta(pick(state, 9) as i32 - 4)
        };
        input.parts_mut()[mi].len = spec;
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, _: Option<libafl::corpus::CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
impl Named for LenLieMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("LenLieMutator")
    }
}

/// Catalog-driven in real use: here a fixed table of (cmd, nargs).
pub struct MsgGenerator(pub Vec<(u8, usize)>);
impl<S: HasRand> Generator<Msg, S> for MsgGenerator {
    fn generate(&mut self, state: &mut S) -> Result<Msg, Error> {
        let (cmd, nargs) = self.0[pick(state, self.0.len())];
        let args = (0..nargs).map(|_| POOL[pick(state, POOL.len())]).collect();
        Ok(Msg { cmd, args, buf: vec![0; 16], len: LenSpec::Derived })
    }
}

#[cfg(test)]
mod tests {
    use libafl::{mutators::list::GenerateToAppendMutator, state::NopState};

    use super::*;

    #[test]
    fn pipeline() {
        let mut st: NopState<Session> = NopState::new();
        let mut g = MsgGenerator(vec![(0x1a, 2), (0x1b, 0)]);
        let mut s: Session = Session::default();
        let mut app = GenerateToAppendMutator::new(MsgGenerator(vec![(0x1a, 2)]));
        for _ in 0..4 {
            app.mutate(&mut st, &mut s).unwrap();
        }
        s.append_part(g.generate(&mut st).unwrap());
        let mut pool = PoolArgMutator;
        let mut lie = LenLieMutator;
        for _ in 0..50 {
            pool.mutate(&mut st, &mut s).unwrap();
            lie.mutate(&mut st, &mut s).unwrap();
        }
        assert_eq!(s.parts().len(), 5);
        assert_eq!(LenSpec::Delta(-1).resolve(16), 15);
    }
}
