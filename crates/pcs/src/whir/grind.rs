//! Proof-of-work grinding for the WHIR transcripts: the deterministic host
//! search and the hook a device crate registers to accelerate it.

use p3_challenger::GrindingChallenger;

/// An accelerated proof-of-work search, registered for ONE concrete challenger
/// type.
///
/// The accelerator this exists for is a CUDA kernel, and it lives in a crate
/// that DEPENDS on this one.  It cannot be attached through the type system:
/// both the trait it would implement and the challenger it would implement it
/// for would be foreign to that crate, which the orphan rule forbids.  So the
/// accelerator registers itself once, at prover construction, and
/// [`deterministic_grind`] looks up its own `C`.  The lookup is `downcast_ref`,
/// i.e. type-exact — a registration made for a different challenger is simply
/// not found and the host search below runs unchanged.
///
/// The contract an accelerator MUST honour is `deterministic_grind`'s own: it
/// returns the SMALLEST witness index that passes `check_witness`, and it
/// leaves the challenger advanced exactly as one `check_witness(bits, witness)`
/// call would.  Any other witness is still a VALID proof, but a different one —
/// the witness is part of the proof byte stream.
struct GrindAccelerator<C: GrindingChallenger>(fn(&mut C, usize) -> C::Witness);

/// One entry per challenger type, so registering a second challenger cannot
/// silently evict the first.  Written once per challenger at prover
/// construction and read (never written) from the proving threads, so the
/// lock is uncontended; the guard is dropped BEFORE the accelerator runs,
/// because the accelerator is a device call.
static GRIND_ACCELERATORS: std::sync::RwLock<
    alloc::vec::Vec<alloc::boxed::Box<dyn core::any::Any + Send + Sync>>,
> = std::sync::RwLock::new(alloc::vec::Vec::new());

/// Register `accelerator` as the proof-of-work search for challenger `C`.
///
/// Idempotent per challenger and first-writer-wins: re-registering `C` is a
/// no-op, so a process cannot switch grinds half way through a proof.  See
/// [`GrindAccelerator`] for the contract an accelerator must honour.
pub fn register_grind_accelerator<C>(accelerator: fn(&mut C, usize) -> C::Witness)
where
    C: GrindingChallenger + 'static,
{
    let mut registered = GRIND_ACCELERATORS.write().expect("grind accelerator registry poisoned");
    if registered.iter().any(|a| a.is::<GrindAccelerator<C>>()) {
        return;
    }
    registered.push(alloc::boxed::Box::new(GrindAccelerator::<C>(accelerator)));
}

/// Proof of work for challenger `C`, through the registered accelerator when
/// there is one.
///
/// The WHIR query, folding and stripe-batching grinds cannot call
/// [`deterministic_grind`]: their challenger is generic over a field that is
/// only `Field`, while the deterministic search needs to enumerate the prime
/// field's elements.  They can still reach an accelerator, which is what this
/// is for -- without it a registered device grind is used by the LogUp-GKR
/// grind alone and every WHIR grind stays on the host, where one grinding bit
/// doubles a search that runs inside an already-saturated thread pool.
///
/// With no accelerator the inner ring's challenger runs its own `grind`, a
/// SIMD scan over growing windows, so the CPU prover is unchanged there.  Every
/// other challenger runs [`windowed_host_grind`]: the BN254 wrap challenger's
/// own `grind` hands the whole field to one `find_first`, which scans it
/// effectively serially.  Both return the smallest passing witness.
pub(crate) fn accelerated_grind<C>(challenger: &mut C, bits: usize) -> C::Witness
where
    C: GrindingChallenger + Clone + Sync + 'static,
{
    if let Some(accelerated) = grind_accelerator_for::<C>() {
        return accelerated(challenger, bits);
    }
    if core::any::TypeId::of::<C>()
        == core::any::TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        return challenger.grind(bits);
    }
    windowed_host_grind(challenger, bits)
}

/// The registered accelerator for `C`, if one was registered for exactly `C`.
fn grind_accelerator_for<C>() -> Option<fn(&mut C, usize) -> C::Witness>
where
    C: GrindingChallenger + 'static,
{
    GRIND_ACCELERATORS
        .read()
        .expect("grind accelerator registry poisoned")
        .iter()
        .find_map(|a| a.downcast_ref::<GrindAccelerator<C>>())
        .map(|a| a.0)
}

/// Proof of work for challenger `C` that returns the smallest `w ∈ [0, p)`
/// passing `check_witness(bits, w)`, through the registered accelerator when
/// there is one and [`windowed_host_grind`] otherwise.
///
/// The witness must not depend on the machine or the thread-pool size. It is
/// msgpack-encoded (variable length) into the `evaluation_proof_bytes` the
/// next layer reads, so its size moves the witness-read instruction count,
/// the `RecursionShapeConfig::fix_shape` selection, and hence
/// `compressed_proof.vk.hash_koalabear()`. The smallest witness is the same
/// on every run, machine and thread-pool size.
pub(crate) fn deterministic_grind<F, C>(challenger: &mut C, bits: usize) -> F
where
    F: p3_field::PrimeField64 + Send + Sync,
    C: GrindingChallenger<Witness = F> + Clone + Sync + 'static,
{
    if bits == 0 {
        return F::ZERO;
    }
    if let Some(accelerated) = grind_accelerator_for::<C>() {
        return accelerated(challenger, bits);
    }
    windowed_host_grind(challenger, bits)
}

/// The host search of [`deterministic_grind`]: the smallest witness index that
/// passes `check_witness(bits, ·)`, scanned in parallel over growing windows,
/// with the challenger then advanced by that one check.
///
/// Each window is a parallel `find_first`, whose left-of-match cancellation
/// returns the smallest index independent of scheduling.  The windows start
/// `2^bits` wide and double, rather than covering `[0, p)` at once.  The
/// smallest witness inside the first non-empty window is the smallest overall,
/// so the result is identical, but a `find_first` handed the whole field builds
/// its task tree over billions of indices and cancels only at chunk
/// boundaries, which costs far more than the search itself.  The first window
/// is the expected distance to a witness, so the search usually ends there.
///
/// Indices map to witnesses by `from_u64`, which is the identity below the
/// field order; every challenger here grinds a 32-bit field, so the scan is
/// bounded there.
fn windowed_host_grind<C>(challenger: &mut C, bits: usize) -> C::Witness
where
    C: GrindingChallenger + Clone + Sync,
{
    use p3_field::PrimeCharacteristicRing;
    use p3_maybe_rayon::prelude::*;
    if bits == 0 {
        return C::Witness::ZERO;
    }
    let end = 1u64 << 32;
    let mut lo = 0u64;
    let mut span = 1u64 << bits.min(32);
    let witness = loop {
        let hi = core::cmp::min(end, lo.saturating_add(span));
        let found = (lo..hi).into_par_iter().map(C::Witness::from_u64).find_first(|&w| {
            let mut probe = challenger.clone();
            probe.check_witness(bits, w)
        });
        if let Some(w) = found {
            break w;
        }
        assert!(hi < end, "windowed_host_grind: failed to find a PoW witness");
        lo = hi;
        span = span.saturating_mul(2);
    };
    let ok = challenger.check_witness(bits, witness);
    debug_assert!(ok);
    witness
}
