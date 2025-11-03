#pragma once

#include "zkm-core-machine-sys-cbindgen.hpp"

#ifndef __CUDACC__
    #define __ZKM_HOSTDEV__
    #define __ZKM_INLINE__ inline
    #include <array>

namespace zkm_core_machine_sys {
template<class T, std::size_t N>
using array_t = std::array<T, N>;
}  // namespace zkm
#else
    #define __ZKM_HOSTDEV__ __host__ __device__
    #define __ZKM_INLINE__ 
    #include <cuda/std/array>

namespace zkm_core_machine_sys {
template<class T, std::size_t N>
using array_t = cuda::std::array<T, N>;
}  // namespace zkm
#endif
