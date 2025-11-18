use openvm_stark_backend::interaction::{InteractionBuilder, LookupBus};
use p3_field::FieldAlgebra;

use crate::chips::byte::ByteLookupOp;

/// Represents a bus for `(x, y, x ^ y)` identified by a unique bus index (`usize`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteLookupBus(pub LookupBus);

impl ByteLookupBus {
    pub fn send<T>(
        &self,
        x: impl Into<T>,
        y: impl Into<T>,
        op: ByteLookupOp,
        res: Vec<impl Into<T>>,
    ) -> ByteBusInteraction<T> {
        self.push(x, y, op, res, true)
    }

    pub fn receive<T>(
        &self,
        x: impl Into<T>,
        y: impl Into<T>,
        op: ByteLookupOp,
        res: Vec<impl Into<T>>,
    ) -> ByteBusInteraction<T> {
        self.push(x, y, op, res, false)
    }

    pub fn push<T>(
        &self,
        x: impl Into<T>,
        y: impl Into<T>,
        op: ByteLookupOp,
        res: Vec<impl Into<T>>,
        is_lookup: bool,
    ) -> ByteBusInteraction<T> {
        ByteBusInteraction {
            x: x.into(),
            y: y.into(),
            op,
            res: res.into_iter().map(|r| r.into()).collect(),
            bus: self.0,
            is_lookup,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ByteBusInteraction<T> {
    pub x: T,
    pub y: T,
    pub op: ByteLookupOp,
    pub res: Vec<T>,
 
    pub bus: LookupBus,
    pub is_lookup: bool,
}

impl<T: FieldAlgebra> ByteBusInteraction<T> {
    /// Finalizes and sends/receives over the bus.
    pub fn eval<AB>(self, builder: &mut AB, count: impl Into<AB::Expr>)
    where
        AB: InteractionBuilder<Expr = T>,
    {
        let mut key = Vec::new();
        key.push(self.x);
        key.push(self.y);
        key.push(T::from_canonical_u8(self.op as u8));
        key.push(self.res[0].clone());
        key.push(self.res[1].clone());
        // key.append(&mut self.res.clone());

        // println!("ByteBusInteraction eval: key={:?}, is_lookup={}", key, self.is_lookup);
        if self.is_lookup {
            self.bus.lookup_key(builder, key, count);
        } else {
            self.bus.add_key_with_lookups(builder, key, count);
        }
    }
}
