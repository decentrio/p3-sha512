use std::
    sync::{
        Arc,
        atomic::{self, AtomicU32},
    }
;

use openvm_stark_backend::{
    Chip, ChipUsageGetter,
    config::{StarkGenericConfig, Val},
    interaction::{BusIndex, LookupBus},
    prover::{cpu::CpuBackend, types::AirProvingContext},
    rap::get_air_name,
};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use strum::EnumIter;

use crate::chips::byte::{
    bus::ByteLookupBus, columns::NUM_BYTE_LOOKUP_COLS, constraints::ByteLookupAir, utils::shr_carry,
};

pub mod bus;
pub mod columns;
pub mod constraints;
pub mod tests;
pub mod utils;

pub use crate::*;

pub const NUM_BYTE_LOOKUP_OPS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum ByteLookupOp {
    Xor,
    ShrCarry,
}

impl ByteLookupOp {
    /// Get all the byte opcodes.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let opcodes = vec![ByteLookupOp::Xor, ByteLookupOp::ShrCarry];
        assert_eq!(opcodes.len(), NUM_BYTE_LOOKUP_OPS);
        opcodes
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

pub struct ByteLookupChip {
    pub air: ByteLookupAir,

    pub count: Vec<Vec<[AtomicU32; NUM_BYTE_LOOKUP_OPS]>>,
}

impl ByteLookupChip {
    pub fn new(bus: BusIndex) -> Self {
        let mut count = vec![];
        for _ in 0..(1 << 8) {
            let mut row = vec![];
            for _ in 0..(1 << 8) {
                let ops = [const { AtomicU32::new(0) }; NUM_BYTE_LOOKUP_OPS];
                row.push(ops);
            }
            count.push(row);
        }
        Self {
            air: ByteLookupAir::new(ByteLookupBus(LookupBus::new(bus))),
            count,
        }
    }

    /// The byte lookup bus this chip interacts with
    pub fn bus(&self) -> ByteLookupBus {
        self.air.bus
    }

    fn calc_xor(&self, x: u8, y: u8) -> u8 {
        x ^ y
    }

    /// Request an XOR operation for inputs x and y
    /// Increments the count for this (x,y) pair and returns x ⊕ y
    pub fn request(&self, x: u8, y: u8, op: ByteLookupOp) -> Vec<u8> {
        let val_atomic = &self.count[x as usize][y as usize][op as usize];

        match op {
            ByteLookupOp::Xor => {
                val_atomic.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                vec![self.calc_xor(x, y), 0]
            }
            ByteLookupOp::ShrCarry => {
                val_atomic.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (shr, carry) = shr_carry(x, y);
                vec![shr, carry]
            }
        }
    }

    /// Resets all request counters to zero
    pub fn clear(&self) {
        for i in 0..(1 << 8) {
            for j in 0..(1 << 8) {
                for k in 0..NUM_BYTE_LOOKUP_OPS {
                    self.count[i][j][k].store(0, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// Generates the multiplicity trace based on requests
    pub fn generate_trace<F: Field>(&self) -> RowMajorMatrix<F> {
        debug_assert_eq!(self.count.len(), 1 << 8);
        let multiplicities: Vec<F> = self
            .count
            .iter()
            .flat_map(|count_x| {
                debug_assert_eq!(count_x.len(), 1 << 8);
                count_x.iter().flat_map(|count_xy| {
                    count_xy
                        .iter()
                        .map(|op| F::from_canonical_u32(op.load(atomic::Ordering::SeqCst)))
                })
            })
            .collect();

        RowMajorMatrix::new(multiplicities, NUM_BYTE_LOOKUP_COLS)
    }
}

impl<R, SC: StarkGenericConfig> Chip<R, CpuBackend<SC>> for ByteLookupChip {
    fn generate_proving_ctx(&self, _: R) -> AirProvingContext<CpuBackend<SC>> {
        let trace = self.generate_trace::<Val<SC>>();
        AirProvingContext::simple_no_pis(Arc::new(trace))
    }
}

impl ChipUsageGetter for ByteLookupChip {
    fn air_name(&self) -> String {
        get_air_name(&self.air)
    }

    fn current_trace_height(&self) -> usize {
        1 << (2 * 8)
    }

    fn trace_width(&self) -> usize {
        NUM_BYTE_LOOKUP_COLS
    }
}
