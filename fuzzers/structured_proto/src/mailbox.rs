//! Typed mailbox session: a sequence of BIOS->PSP messages, each laid out from the catalog.
//! Mutators are field-aware (havoc only inside typed fields), derive TotalSize at render time
//! (a deliberately wrong size is an explicit `LenSpec`), and perturb command sequences around
//! a valid prefix. All randomness comes from the fuzzer state (deterministic).
use std::{borrow::Cow, num::NonZeroUsize, sync::Arc};

use libafl::{
    Error,
    corpus::CorpusId,
    generators::Generator,
    inputs::{Input, ListInput},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};
use serde::{Deserialize, Serialize};

use crate::{LenSpec, catalog::Catalog};

/// One mailbox message: command id, argument buffer (TotalSize@0, Status@4, args from 8),
/// and the CmdRspBufAddr lo/hi words.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct MbMsg {
    pub cmd: u32,
    pub buf: Vec<u8>,
    pub total_size: LenSpec,
    pub buf_lo: u32,
    pub buf_hi: u32,
}
impl Input for MbMsg {}
pub type MbSession = ListInput<MbMsg>;

impl MbMsg {
    /// Bytes to place in the mapped buffer. TotalSize is derived from the buffer unless overridden.
    pub fn render(&self) -> Vec<u8> {
        let mut b = self.buf.clone();
        if b.len() < 8 {
            b.resize(8, 0);
        }
        let total = self.total_size.resolve(b.len());
        b[0..4].copy_from_slice(&total.to_le_bytes());
        b
    }
}

const POOL: &[u64] = &[
    0, 1, 2, 3, 4, 8, 0xf, 0x10, 0x20, 0x7f, 0x80, 0xff, 0x100, 0x110, 0x111, 0x1000, 0xffff,
    0x1_0000, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_fffe, 0xffff_ffff,
    0x3_f000, 0x4_0000, 0x20_0000, 0x0100_0000, 0x0400_0000, 0xfb00_0000,
    0x1_0000_0000, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xfffd_fb00_0000, u64::MAX,
];

fn below<S: HasRand>(state: &mut S, n: usize) -> usize {
    state.rand_mut().below(NonZeroUsize::new(n).unwrap())
}

fn mask(width: usize) -> u64 {
    if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 }
}

fn write_le(buf: &mut [u8], off: usize, width: usize, v: u64) -> bool {
    if off + width > buf.len() {
        return false;
    }
    buf[off..off + width].copy_from_slice(&v.to_le_bytes()[..width]);
    true
}

fn read_le(buf: &[u8], off: usize, width: usize) -> Option<u64> {
    let s = buf.get(off..off + width)?;
    let mut a = [0u8; 8];
    a[..width].copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// A value for a field of `width` bytes: pool, power of two +-1, small, the sign bit, or `old` perturbed.
fn typed_value<S: HasRand>(state: &mut S, width: usize, old: u64) -> u64 {
    let bits = (width * 8) as u32;
    let v = match below(state, 6) {
        0 => POOL[below(state, POOL.len())],
        1 => {
            let p = 1u64 << below(state, bits as usize);
            [p.wrapping_sub(1), p, p.wrapping_add(1)][below(state, 3)]
        }
        2 => below(state, 0x400) as u64,
        3 => old ^ (1u64 << (bits - 1)), // flip the sign bit: signed/unsigned size checks
        4 => old.wrapping_add_signed(below(state, 33) as i64 - 16),
        _ => old ^ (1u64 << below(state, bits as usize)),
    };
    v & mask(width)
}

/// Fill the typed fields of `buf` with fresh values.
fn fill_fields<S: HasRand>(state: &mut S, cat: &Catalog, cmd: u32, buf: &mut [u8]) {
    if let Some(c) = cat.command(cmd) {
        for (off, w) in c.arg_layout.iter().filter_map(|f| f.scalar()) {
            let v = typed_value(state, w, 0);
            write_le(buf, off, w, v);
        }
    }
}

fn new_msg<S: HasRand>(state: &mut S, cat: &Catalog, cmd: u32) -> MbMsg {
    let len = cat.command(cmd).map_or(16, |c| c.buf_len());
    let mut buf = vec![0u8; len];
    fill_fields(state, cat, cmd, &mut buf);
    MbMsg { cmd, buf, total_size: LenSpec::Derived, buf_lo: 0x0400_0000, buf_hi: 0 }
}

/// Generator for single messages and valid-prefix sessions.
pub struct MbGenerator {
    pub catalog: Arc<Catalog>,
}
impl<S: HasRand> Generator<MbMsg, S> for MbGenerator {
    fn generate(&mut self, state: &mut S) -> Result<MbMsg, Error> {
        let n = self.catalog.commands.len();
        if n == 0 {
            return Err(Error::empty("empty catalog"));
        }
        let id = self.catalog.commands[below(state, n)].id;
        Ok(new_msg(state, &self.catalog, id))
    }
}

macro_rules! named {
    ($t:ty, $n:expr) => {
        impl Named for $t {
            fn name(&self) -> &Cow<'static, str> {
                static N: Cow<'static, str> = Cow::Borrowed($n);
                &N
            }
        }
    };
}

fn nop_post(_: Option<CorpusId>) -> Result<(), Error> {
    Ok(())
}

/// Mutate ONE typed field of ONE message (havoc only inside typed fields).
pub struct FieldMutator {
    pub catalog: Arc<Catalog>,
}
named!(FieldMutator, "MbFieldMutator");
impl<S: HasRand> Mutator<MbSession, S> for FieldMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        let cmd = input.parts()[mi].cmd;
        let Some(c) = self.catalog.command(cmd) else {
            return Ok(MutationResult::Skipped);
        };
        let scalars: Vec<(usize, usize)> = c.arg_layout.iter().filter_map(|f| f.scalar()).collect();
        if scalars.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let (off, w) = scalars[below(state, scalars.len())];
        let old = read_le(&input.parts()[mi].buf, off, w).unwrap_or(0);
        let v = typed_value(state, w, old);
        let ok = write_le(&mut input.parts_mut()[mi].buf, off, w, v);
        Ok(if ok && v != old { MutationResult::Mutated } else { MutationResult::Skipped })
    }
    fn post_exec(&mut self, _: &mut S, id: Option<CorpusId>) -> Result<(), Error> {
        nop_post(id)
    }
}

/// Make TotalSize deliberately inconsistent with the buffer (the knob; keep its weight low).
pub struct SizeLieMutator;
named!(SizeLieMutator, "MbSizeLieMutator");
impl<S: HasRand> Mutator<MbSession, S> for SizeLieMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        input.parts_mut()[mi].total_size = match below(state, 3) {
            0 => LenSpec::Override(POOL[below(state, POOL.len())] as u32),
            1 => LenSpec::Delta(below(state, 17) as i32 - 8),
            _ => LenSpec::Derived, // allows returning to a consistent size
        };
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, id: Option<CorpusId>) -> Result<(), Error> {
        nop_post(id)
    }
}

/// CmdRspBufAddr lo/hi: mapped x86 region, 4 KiB-aligned or not, secure-DRAM-ish and wild values.
pub struct BufPtrMutator;
named!(BufPtrMutator, "MbBufPtrMutator");
impl<S: HasRand> Mutator<MbSession, S> for BufPtrMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        if n == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        let r = state.rand_mut().next();
        let m = &mut input.parts_mut()[mi];
        match r % 4 {
            0 => m.buf_lo = 0x0400_0000 + (((r >> 8) as u32 % 0xf8) << 20) + ((r >> 32) as u32 & 0xfff),
            1 => m.buf_lo = ((r >> 8) as u32) & 0xffff_f000,
            2 => {
                m.buf_lo = 0xfb00_0000 | ((r >> 8) as u32 & 0xfff);
                m.buf_hi = 0xfffd;
            }
            _ => {
                m.buf_lo = POOL[(r >> 8) as usize % POOL.len()] as u32;
                m.buf_hi = (POOL[(r >> 20) as usize % POOL.len()] >> 32) as u32;
            }
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, id: Option<CorpusId>) -> Result<(), Error> {
        nop_post(id)
    }
}

/// Change a message's command (arguments regenerated from the new layout, buffer resized).
pub struct CmdMutator {
    pub catalog: Arc<Catalog>,
}
named!(CmdMutator, "MbCmdMutator");
impl<S: HasRand> Mutator<MbSession, S> for CmdMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        let k = self.catalog.commands.len();
        if n == 0 || k == 0 {
            return Ok(MutationResult::Skipped);
        }
        let mi = below(state, n);
        // 1 in 8: an id that is not in the catalog (negative control, should give status 4)
        let id = if below(state, 8) == 0 {
            below(state, 0x100) as u32
        } else {
            self.catalog.commands[below(state, k)].id
        };
        if id == input.parts()[mi].cmd {
            return Ok(MutationResult::Skipped);
        }
        let mut m = new_msg(state, &self.catalog, id);
        let old = &input.parts()[mi];
        (m.buf_lo, m.buf_hi) = (old.buf_lo, old.buf_hi);
        input.parts_mut()[mi] = m;
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, id: Option<CorpusId>) -> Result<(), Error> {
        nop_post(id)
    }
}

/// Sequence mutator: start from a VALID prefix (a known-good command order, e.g. 0x1b before 0x06),
/// then perturb: drop, duplicate, swap adjacent, insert a random command, truncate.
pub struct SequenceMutator {
    pub catalog: Arc<Catalog>,
    /// known-good command orders (preconditions), e.g. [[0x1b, 0x06], [0x02, 0x28, 0x29, 0x2a]]
    pub valid: Vec<Vec<u32>>,
}
named!(SequenceMutator, "MbSequenceMutator");
impl<S: HasRand> Mutator<MbSession, S> for SequenceMutator {
    fn mutate(&mut self, state: &mut S, input: &mut MbSession) -> Result<MutationResult, Error> {
        let n = input.parts().len();
        let k = self.catalog.commands.len();
        if k == 0 {
            return Ok(MutationResult::Skipped);
        }
        match below(state, 6) {
            // replace the session by a prefix of a valid sequence
            0 if !self.valid.is_empty() => {
                let seq = &self.valid[below(state, self.valid.len())];
                let take = 1 + below(state, seq.len());
                let ids: Vec<u32> = seq[..take].to_vec();
                let parts: Vec<MbMsg> = ids.iter().map(|&i| new_msg(state, &self.catalog, i)).collect();
                *input = MbSession::new(parts);
            }
            1 if n > 1 => input.remove_part_at_index(below(state, n)),
            2 if n > 0 => {
                let i = below(state, n);
                let c = input.parts()[i].clone();
                input.insert_part(i, c);
            }
            3 if n > 1 => {
                let i = below(state, n - 1);
                input.parts_mut().swap(i, i + 1);
            }
            4 if n > 1 => {
                let keep = 1 + below(state, n - 1);
                while input.len() > keep {
                    input.pop_part();
                }
            }
            _ => {
                let id = self.catalog.commands[below(state, k)].id;
                let m = new_msg(state, &self.catalog, id);
                input.insert_part(below(state, n + 1), m);
            }
        }
        Ok(MutationResult::Mutated)
    }
    fn post_exec(&mut self, _: &mut S, id: Option<CorpusId>) -> Result<(), Error> {
        nop_post(id)
    }
}

#[cfg(test)]
mod tests {
    use libafl::state::NopState;

    use super::*;

    // Synthetic catalog (the real one is AMD-derived and local-only, never committed).
    const CAT: &str = r#"{"commands":[
      {"id":2,"name":"A","arg_layout":[{"name":"x","type":"u64","offset":8},{"name":"y","type":"u32","offset":16}],"maps_buffer":false},
      {"id":27,"name":"B","arg_layout":[]},
      {"id":6,"name":"C","arg_layout":[{"name":"f","type":"u8","offset":8}],"arg_size":32}]}"#;

    fn cat() -> Arc<Catalog> {
        Arc::new(Catalog::from_json(CAT).unwrap())
    }

    #[test]
    fn catalog_buf_len() {
        let c = cat();
        assert_eq!(c.command(2).unwrap().buf_len(), 20);
        assert_eq!(c.command(27).unwrap().buf_len(), 8);
        assert_eq!(c.command(6).unwrap().buf_len(), 32);
    }

    #[test]
    fn render_derives_total_size_unless_overridden() {
        let mut m = MbMsg { cmd: 2, buf: vec![0; 20], total_size: LenSpec::Derived, buf_lo: 0, buf_hi: 0 };
        assert_eq!(&m.render()[0..4], &20u32.to_le_bytes());
        m.total_size = LenSpec::Override(0x8000_0000);
        assert_eq!(&m.render()[0..4], &0x8000_0000u32.to_le_bytes());
        m.total_size = LenSpec::Delta(-1);
        assert_eq!(&m.render()[0..4], &19u32.to_le_bytes());
    }

    #[test]
    fn field_mutator_only_touches_typed_fields() {
        let c = cat();
        let mut st: NopState<MbSession> = NopState::new();
        let mut g = MbGenerator { catalog: c.clone() };
        let mut fm = FieldMutator { catalog: c.clone() };
        let mut s = MbSession::new(vec![new_msg(&mut st, &c, 2)]);
        let _ = &mut g;
        let before = s.parts()[0].buf.clone();
        for _ in 0..200 {
            fm.mutate(&mut st, &mut s).unwrap();
        }
        let after = &s.parts()[0].buf;
        assert_eq!(after.len(), 20);
        // header (0..8) and the gap byte range 20.. untouched; only x@8..16 and y@16..20 may change
        assert_eq!(&before[0..8], &after[0..8]);
        assert!(after[8..20] != before[8..20], "fields never changed");
    }

    #[test]
    fn sequences_start_from_valid_prefix_and_stay_nonempty() {
        let c = cat();
        let mut st: NopState<MbSession> = NopState::new();
        let mut sm = SequenceMutator { catalog: c.clone(), valid: vec![vec![27, 6]] };
        let mut s = MbSession::new(vec![]);
        let mut saw_valid = false;
        for _ in 0..300 {
            sm.mutate(&mut st, &mut s).unwrap();
            if s.parts().iter().map(|m| m.cmd).collect::<Vec<_>>() == vec![27, 6] {
                saw_valid = true;
            }
        }
        assert!(saw_valid);
    }

    /// Optional: parse the real (local-only) catalog if MAILBOX_CATALOG points at it.
    #[test]
    fn real_catalog_parses_if_present() {
        let Ok(p) = std::env::var("MAILBOX_CATALOG") else { return };
        let c = Catalog::from_json(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert!(c.commands.len() > 10);
        let mut st: NopState<MbSession> = NopState::new();
        for cmd in &c.commands {
            let m = new_msg(&mut st, &c, cmd.id);
            assert_eq!(m.buf.len(), cmd.buf_len());
        }
    }

    #[test]
    fn cmd_size_ptr_mutators_run_and_buffers_match_layout() {
        let c = cat();
        let mut st: NopState<MbSession> = NopState::new();
        let mut s = MbSession::new(vec![new_msg(&mut st, &c, 2), new_msg(&mut st, &c, 6)]);
        let mut cm = CmdMutator { catalog: c.clone() };
        let mut sz = SizeLieMutator;
        let mut bp = BufPtrMutator;
        for _ in 0..500 {
            cm.mutate(&mut st, &mut s).unwrap();
            sz.mutate(&mut st, &mut s).unwrap();
            bp.mutate(&mut st, &mut s).unwrap();
            for m in s.parts() {
                if let Some(cmd) = c.command(m.cmd) {
                    assert_eq!(m.buf.len(), cmd.buf_len(), "cmd {}", m.cmd);
                }
                assert!(m.render().len() >= 8);
            }
        }
    }
}
