// memcmp / bcmp for the mipsel-zkm-zkvm-elf guest.
//
// Without this the guest links compiler_builtins' generic memcmp, a byte
// loop: every 32-byte U256 comparison in the EVM interpreter (jumpi, iszero,
// eq) and every hash-map key compare cost ~4 cycles per byte. A traced reth
// block spent 36 M of 401 M cycles (9%) inside it.
//
// Word-at-a-time when both pointers are 4-byte aligned; the first mismatching
// word is resolved bytewise so the result is the C one: the difference of the
// first differing bytes as unsigned chars. bcmp shares the code (only
// zero / non-zero is specified for it).
	.text
	.globl	memcmp
	.globl	bcmp
	.p2align	2
	.type	memcmp,@function
	.type	bcmp,@function
	.set	nomicromips
	.set	nomips16
	.ent	memcmp
memcmp:
bcmp:
	.frame	$sp,0,$ra
	.set	noreorder
	.set	nomacro
	.set	noat
	or	$1, $4, $5
	andi	$1, $1, 3
	bnez	$1, .Lmemcmp_bytes
	nop
	sltiu	$1, $6, 4
	bnez	$1, .Lmemcmp_bytes
	nop
	sltiu	$1, $6, 16
	bnez	$1, .Lmemcmp_words
	nop
.Lmemcmp_words4:
	# four words per iteration while >= 16 bytes remain (U256 compares are
	# exactly 32 bytes: two iterations, one loop overhead each)
	lw	$7, 0($4)
	lw	$8, 0($5)
	bne	$7, $8, .Lmemcmp_bytes
	nop
	lw	$7, 4($4)
	lw	$8, 4($5)
	bne	$7, $8, .Lmemcmp_diff4
	nop
	lw	$7, 8($4)
	lw	$8, 8($5)
	bne	$7, $8, .Lmemcmp_diff8
	nop
	lw	$7, 12($4)
	lw	$8, 12($5)
	bne	$7, $8, .Lmemcmp_diff12
	nop
	addiu	$4, $4, 16
	addiu	$5, $5, 16
	addiu	$6, $6, -16
	sltiu	$1, $6, 16
	beqz	$1, .Lmemcmp_words4
	nop
	sltiu	$1, $6, 4
	bnez	$1, .Lmemcmp_bytes
	nop
.Lmemcmp_words:
	lw	$7, 0($4)
	lw	$8, 0($5)
	bne	$7, $8, .Lmemcmp_bytes
	nop
	addiu	$4, $4, 4
	addiu	$5, $5, 4
	addiu	$6, $6, -4
	sltiu	$1, $6, 4
	beqz	$1, .Lmemcmp_words
	nop
	b	.Lmemcmp_bytes
	nop
.Lmemcmp_diff12:
	addiu	$4, $4, 4
	addiu	$5, $5, 4
	addiu	$6, $6, -4
.Lmemcmp_diff8:
	addiu	$4, $4, 4
	addiu	$5, $5, 4
	addiu	$6, $6, -4
.Lmemcmp_diff4:
	addiu	$4, $4, 4
	addiu	$5, $5, 4
	addiu	$6, $6, -4
.Lmemcmp_bytes:
	beqz	$6, .Lmemcmp_eq
	nop
.Lmemcmp_byte_loop:
	lbu	$7, 0($4)
	lbu	$8, 0($5)
	bne	$7, $8, .Lmemcmp_diff
	nop
	addiu	$4, $4, 1
	addiu	$5, $5, 1
	addiu	$6, $6, -1
	bnez	$6, .Lmemcmp_byte_loop
	nop
.Lmemcmp_eq:
	jr	$ra
	move	$2, $zero
.Lmemcmp_diff:
	jr	$ra
	subu	$2, $7, $8
	.set	at
	.set	macro
	.set	reorder
	.end	memcmp
	.size	memcmp, .-memcmp
