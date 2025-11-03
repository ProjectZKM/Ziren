#pragma once

#include "zkm-recursion-core-sys-cbindgen.hpp"

#ifndef __CUDACC__
#define __ZKM_HOSTDEV__
#define __ZKM_INLINE__ inline
#include <array>

namespace zkm_recursion_core_sys {
template <class T, std::size_t N>
using array_t = std::array<T, N>;
}  // namespace zkm_recursion_core_sys
#else
#define __ZKM_HOSTDEV__ __host__ __device__
#define __ZKM_INLINE__ __forceinline__
#include <cuda/std/array>

namespace zkm_recursion_core_sys {
template <class T, std::size_t N>
using array_t = cuda::std::array<T, N>;
}  // namespace zkm_recursion_core_sys
#endif
