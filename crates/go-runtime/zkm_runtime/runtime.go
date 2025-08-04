//go:build mipsle
// +build mipsle

package zkm_runtime
import (
	"encoding/binary"
	"crypto/sha256"
	"hash"
	_ "unsafe"
	"reflect"
)

func SyscallWrite(fd int, write_buf []byte, nbytes int) int
func SyscallHintLen() int
func SyscallHintRead(ptr []byte, len int)
func SyscallCommit(index int, word uint32)
func SyscallExit(code int)

var PublicValuesHasher hash.Hash = sha256.New()

func Read[T any]() T {
	len := SyscallHintLen()
	var value []byte
	capacity := (len + 3) / 4 * 4
	value = make([]byte, capacity)
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
