//go:build mipsle
// +build mipsle

package zkvm_runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"reflect"
	"unsafe"
)

func SyscallWrite(fd int, write_buf []byte, nbytes int) int
func SyscallHintLen() int
func SyscallHintRead(ptr []byte, len int)
func SyscallCommit(index int, word uint32)
func SyscallExit(code int)

var PublicValuesHasher hash.Hash = sha256.New()

const EMBEDDED_RESERVED_INPUT_REGION_SIZE int = 1024 * 1024 * 1024
const MAX_MEMORY int = 0x7ff00000

var RESERVED_INPUT_PTR int = MAX_MEMORY - EMBEDDED_RESERVED_INPUT_REGION_SIZE

func Read[T any]() T {
	len := SyscallHintLen()
	var value []byte
	capacity := (len + 3) / 4 * 4
	addr := RESERVED_INPUT_PTR
	RESERVED_INPUT_PTR += capacity
	ptr := unsafe.Pointer(uintptr(addr))
	value = unsafe.Slice((*byte)(ptr), capacity)
	var result T
	SyscallHintRead(value, len)
	DeserializeData(value[0:len], &result)
	return result
}

func Commit[T any](value T) {
	bytes := MustSerializeData(value)
	length := len(bytes)
	if (length & 3) != 0 {
		d := make([]byte, 4-(length&3))
		bytes = append(bytes, d...)
	}

	_, _ = PublicValuesHasher.Write(bytes)

	SyscallWrite(13, bytes, length)
}

//go:linkname RuntimeExit zkvm.RuntimeExit
func RuntimeExit(code int) {
	hashBytes := PublicValuesHasher.Sum(nil)

	// 2. COMMIT each u32 word
	for i := 0; i < 8; i++ {
		word := binary.LittleEndian.Uint32(hashBytes[i*4 : (i+1)*4])
		SyscallCommit(i, word)
	}

	SyscallExit(code)
}

func init() {
	// 显式引用，防止优化
	_ = reflect.ValueOf(RuntimeExit)
}
