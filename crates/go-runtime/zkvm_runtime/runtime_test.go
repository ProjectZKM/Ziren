//go:build mipsle
// +build mipsle

package zkvm_runtime

import "testing"

func TestReadReservedInputAdvancesPointer(t *testing.T) {
	oldPtr := RESERVED_INPUT_PTR
	defer func() { RESERVED_INPUT_PTR = oldPtr }()

	RESERVED_INPUT_PTR = MAX_MEMORY - EMBEDDED_RESERVED_INPUT_REGION_SIZE
	addr := readReservedInput(16)
	if addr != MAX_MEMORY-EMBEDDED_RESERVED_INPUT_REGION_SIZE {
		t.Fatalf("unexpected addr: got %x want %x", addr, MAX_MEMORY-EMBEDDED_RESERVED_INPUT_REGION_SIZE)
	}
	if RESERVED_INPUT_PTR != addr+16 {
		t.Fatalf("unexpected ptr: got %x want %x", RESERVED_INPUT_PTR, addr+16)
	}
}

func TestReadReservedInputPanicsOnOverflow(t *testing.T) {
	oldPtr := RESERVED_INPUT_PTR
	defer func() { RESERVED_INPUT_PTR = oldPtr }()

	RESERVED_INPUT_PTR = MAX_MEMORY - 8
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on overflow")
		}
	}()
	_ = readReservedInput(16)
}
