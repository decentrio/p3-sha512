use openvm_stark_backend::p3_air::AirBuilder;

/// Trait with associated types intended to allow reuse of constraint logic
/// inside other AIRs.
///
/// A `SubAir` is **not** an [Air](openvm_stark_backend::p3_air::Air) itself.
/// A `SubAir` is a struct that holds the means to generate a particular set of constraints,
/// meant to be reusable within other AIRs.
///
/// The trait is designed to be maximally flexible, but typical implementations will separate
/// the `AirContext` into two parts: `Io` and `AuxCols`. The `Io` part will consist of
/// expressions (built using `AB::Expr`) that the `SubAir` does not own, while the `AuxCols`
/// are any internal columns that the `SubAir` requires to generate its constraints. The
/// `AuxCols` are columns that the `SubAir` fully owns and should be internally determined by
/// the `SubAir` from the `Io` part. These `AuxCols` are typically just slices of `AB::Var`.
///
/// This trait only owns the constraints, but it is expected that the [TraceSubRowGenerator] trait
/// or some analogous functionality is also implemented so that the trace generation of the
/// `AuxCols` of each row can be done purely in terms of the `Io` part.
pub trait SubAir<AB: AirBuilder> {
    /// Type to define the context, typically in terms of `AB::Expr` that are needed
    /// to define the SubAir's constraints.
    type AirContext<'a>
    where
        Self: 'a,
        AB: 'a,
        AB::Var: 'a,
        AB::Expr: 'a;

    fn eval<'a>(&'a self, builder: &'a mut AB, ctx: Self::AirContext<'a>)
    where
        AB::Var: 'a,
        AB::Expr: 'a;
}