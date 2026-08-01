use zkm_derive::AlignedBorrow;
use zkm_pcs::Word;

/// Memory read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadCols<T> {
    pub access: MemoryAccessCols<T>,
}

/// Memory write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

/// Memory read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T> {
    /// The value of the memory access.
    pub value: Word<T>,

    /// The previous shard and timestamp that this memory access is being read from.
    pub prev_shard: T,
    pub prev_clk: T,

    /// This will be true if the current shard == prev_access's shard, else false.
    pub compare_clk: T,

    /// The following columns are decomposed limbs for the difference between the current access's
    /// timestamp and the previous access's timestamp.  Note the actual value of the timestamp
    /// is either the accesses' shard or clk depending on the value of compare_clk.

    /// This column is the least significant 16 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_16bit_limb: T,

    /// This column is the most significant 8 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_8bit_limb: T,
}

/// Register access.
///
/// Register accesses use the same argument and the same address space as memory accesses, but the
/// `MemoryBump` chip inserts a shadow read at `(shard, 0)` on the first touch of a register in a
/// shard.  Since `clk` restarts at 0 every shard and real register accesses live at the sub-cycle
/// positions `1..=4`, that shadow read is always the first link of the shard's access chain, so
/// **every** register access is guaranteed to have `prev_shard == shard`.
///
/// That guarantee removes three columns relative to [`MemoryAccessCols`]:
///  * `prev_shard` — it is `shard`, which the caller already has;
///  * `compare_clk` — it is always 1, so the timestamp check is unconditionally a clk comparison;
///  * `diff_8bit_limb` — the high limb of `clk - prev_clk - 1` is re-derived as the linear
///    expression `(clk - prev_clk - 1 - diff_16bit_limb) / 2^16` and range-checked in place.
///
/// 9 columns -> 6, on every register access of every cycle.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RegisterAccessCols<T> {
    /// The value of the register access.
    pub value: Word<T>,

    /// The clk of the previous access to this register.  Always in the current shard.
    pub prev_clk: T,

    /// The least significant 16 bit limb of `clk - prev_clk - 1`.
    pub diff_16bit_limb: T,
}

/// Register read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RegisterReadCols<T> {
    pub access: RegisterAccessCols<T>,
}

/// Register read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RegisterReadWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: RegisterAccessCols<T>,
}

/// The common columns for all register access types.
pub trait RegisterCols<T> {
    fn access(&self) -> &RegisterAccessCols<T>;

    fn access_mut(&mut self) -> &mut RegisterAccessCols<T>;

    fn prev_value(&self) -> &Word<T>;

    fn prev_value_mut(&mut self) -> &mut Word<T>;

    fn value(&self) -> &Word<T>;

    fn value_mut(&mut self) -> &mut Word<T>;
}

impl<T> RegisterCols<T> for RegisterReadCols<T> {
    fn access(&self) -> &RegisterAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut RegisterAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> RegisterCols<T> for RegisterReadWriteCols<T> {
    fn access(&self) -> &RegisterAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut RegisterAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

/// The common columns for all memory access types.
pub trait MemoryCols<T> {
    fn access(&self) -> &MemoryAccessCols<T>;

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T>;

    fn prev_value(&self) -> &Word<T>;

    fn prev_value_mut(&mut self) -> &mut Word<T>;

    fn value(&self) -> &Word<T>;

    fn value_mut(&mut self) -> &mut Word<T>;
}

impl<T> MemoryCols<T> for MemoryReadCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryReadWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

/// A utility method to convert a slice of memory access columns into a vector of values.
/// This is useful for comparing the values of a memory access to limbs.
pub fn value_as_limbs<T: Clone, M: MemoryCols<T>>(memory: &[M]) -> Vec<T> {
    memory.iter().flat_map(|m| m.value().clone().into_iter()).collect()
}
