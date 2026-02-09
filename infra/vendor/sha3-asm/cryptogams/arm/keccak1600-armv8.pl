#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# Keccak-1600 for ARMv8.
#
# June 2017.
#
# This is straightforward KECCAK_1X_ALT implementation. It makes no
# sense to attempt SIMD/NEON implementation for following reason.
# 64-bit lanes of vector registers can't be addressed as easily as in
# 32-bit mode. This means that 64-bit NEON is bound to be slower than
# 32-bit NEON, and this implementation is faster than 32-bit NEON on
# same processor. Even though it takes more scalar xor's and andn's,
# it gets compensated by availability of rotate. Not to forget that
# most processors achieve higher issue rate with scalar instructions.
#
# February 2018.
#
# Add hardware-assisted ARMv8.2 implementation. It's KECCAK_1X_ALT
# variant with register permutation/rotation twist that allows to
# eliminate copies to temporary registers. If you look closely you'll
# notice that it uses only one lane of vector registers. The new
# instructions effectively facilitate parallel hashing, which we don't
# support [yet?]. But lowest-level core procedure is prepared for it.
# The inner round is 67 [vector] instructions, so it's not actually
# obvious that it will provide performance improvement [in serial
# hash] as long as vector instructions issue rate is limited to 1 per
# cycle...
#
######################################################################
# Numbers are cycles per processed byte.
#
#		r=1088(*)
#
# Cortex-A53	13
# Cortex-A57	12
# Cortex-A76	7.9
# Cortex-X2	6.1 (***)
# X-Gene	14
# Mongoose	10
# Kryo		12
# Denver	7.8
# Apple A7	7.2
# Apple A10	6.1
# Apple A12	4.4
# Apple A14/M1	3.5 (**)
# ThunderX2	9.7
#
# (*)	Corresponds to SHA3-256. No improvement coefficients are listed
#	because they vary too much from compiler to compiler. Newer
#	compiler does much better and improvement varies from 5% on
#	Cortex-A57 to 25% on Cortex-A53. While in comparison to older
#	compiler this code is at least 2x faster...
# (**)	The result is for hardware-assisted implementation below.
# (***)	Hardware-assisted code is significantly slower, 11.3,
#	apparently because the processor can issue just one SHA3
#	instruction per cycle.

$flavour = shift;
$output  = shift;

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

my $sha3ops = ($flavour =~ /\+sha3/);

$code.=<<___	if ($sha3ops);
.arch	armv8.2-a+sha3
___
$code.=<<___;
.text

.align 8	// strategic alignment and padding that allows to use
		// address value as loop termination condition...
	.quad	0,0,0,0,0,0,0,0
.type	iotas,%object
iotas:
	.quad	0x0000000000000001
	.quad	0x0000000000008082
	.quad	0x800000000000808a
	.quad	0x8000000080008000
	.quad	0x000000000000808b
	.quad	0x0000000080000001
	.quad	0x8000000080008081
	.quad	0x8000000000008009
	.quad	0x000000000000008a
	.quad	0x0000000000000088
	.quad	0x0000000080008009
	.quad	0x000000008000000a
.Liotas12:
	.quad	0x000000008000808b
	.quad	0x800000000000008b
	.quad	0x8000000000008089
	.quad	0x8000000000008003
	.quad	0x8000000000008002
	.quad	0x8000000000000080
	.quad	0x000000000000800a
	.quad	0x800000008000000a
	.quad	0x8000000080008081
	.quad	0x8000000000008080
	.quad	0x0000000080000001
	.quad	0x8000000080008008
.size	iotas,.-iotas
___
								{{{
my @A = map([ "x$_", "x".($_+1), "x".($_+2), "x".($_+3), "x".($_+4) ],
            (0, 5, 10, 15, 20));
   $A[3][3] = "x25"; # x18 is reserved

my @C = map("x$_", (26,27,28,30));

$code.=<<___;
.type	KeccakF1600_int,%function
.align	5
KeccakF1600_int:
	.inst	0xd503233f			// paciasp
	stp	c#$C[2],c30,[csp,#16]		// stack is pre-allocated
	b	.Loop
.align	4
.Loop:
	////////////////////////////////////////// Theta
	eor	$C[0],$A[0][0],$A[1][0]
	stp	$A[0][4],$A[1][4],[sp,#0]	// offload pair...
	eor	$C[1],$A[0][1],$A[1][1]
	eor	$C[2],$A[0][2],$A[1][2]
	eor	$C[3],$A[0][3],$A[1][3]
___
	$C[4]=$A[0][4];
	$C[5]=$A[1][4];
$code.=<<___;
	eor	$C[4],$A[0][4],$A[1][4]
	eor	$C[0],$C[0],$A[2][0]
	eor	$C[1],$C[1],$A[2][1]
	eor	$C[2],$C[2],$A[2][2]
	eor	$C[3],$C[3],$A[2][3]
	eor	$C[4],$C[4],$A[2][4]
	eor	$C[0],$C[0],$A[3][0]
	eor	$C[1],$C[1],$A[3][1]
	eor	$C[2],$C[2],$A[3][2]
	eor	$C[3],$C[3],$A[3][3]
	eor	$C[4],$C[4],$A[3][4]
	eor	$C[0],$C[0],$A[4][0]
	eor	$C[2],$C[2],$A[4][2]
	eor	$C[1],$C[1],$A[4][1]
	eor	$C[3],$C[3],$A[4][3]
	eor	$C[4],$C[4],$A[4][4]

	eor	$C[5],$C[0],$C[2],ror#63

	eor	$A[0][1],$A[0][1],$C[5]
	eor	$A[1][1],$A[1][1],$C[5]
	eor	$A[2][1],$A[2][1],$C[5]
	eor	$A[3][1],$A[3][1],$C[5]
	eor	$A[4][1],$A[4][1],$C[5]

	eor	$C[5],$C[1],$C[3],ror#63
	eor	$C[2],$C[2],$C[4],ror#63
	eor	$C[3],$C[3],$C[0],ror#63
	eor	$C[4],$C[4],$C[1],ror#63

	eor	$C[1],   $A[0][2],$C[5]		// mov	$C[1],$A[0][2]
	eor	$A[1][2],$A[1][2],$C[5]
	eor	$A[2][2],$A[2][2],$C[5]
	eor	$A[3][2],$A[3][2],$C[5]
	eor	$A[4][2],$A[4][2],$C[5]

	eor	$A[0][0],$A[0][0],$C[4]
	eor	$A[1][0],$A[1][0],$C[4]
	eor	$A[2][0],$A[2][0],$C[4]
	eor	$A[3][0],$A[3][0],$C[4]
	eor	$A[4][0],$A[4][0],$C[4]
___
	$C[4]=undef;
	$C[5]=undef;
$code.=<<___;
	ldp	$A[0][4],$A[1][4],[sp,#0]	// re-load offloaded data
	eor	$C[0],   $A[0][3],$C[2]		// mov	$C[0],$A[0][3]
	eor	$A[1][3],$A[1][3],$C[2]
	eor	$A[2][3],$A[2][3],$C[2]
	eor	$A[3][3],$A[3][3],$C[2]
	eor	$A[4][3],$A[4][3],$C[2]

	eor	$C[2],   $A[0][4],$C[3]		// mov	$C[2],$A[0][4]
	eor	$A[1][4],$A[1][4],$C[3]
	eor	$A[2][4],$A[2][4],$C[3]
	eor	$A[3][4],$A[3][4],$C[3]
	eor	$A[4][4],$A[4][4],$C[3]

	////////////////////////////////////////// Rho+Pi
	mov	$C[3],$A[0][1]
	ror	$A[0][1],$A[1][1],#64-$rhotates[1][1]
	//mov	$C[1],$A[0][2]
	ror	$A[0][2],$A[2][2],#64-$rhotates[2][2]
	//mov	$C[0],$A[0][3]
	ror	$A[0][3],$A[3][3],#64-$rhotates[3][3]	// ?
	//mov	$C[2],$A[0][4]
	ror	$A[0][4],$A[4][4],#64-$rhotates[4][4]	// ?

	ror	$A[1][1],$A[1][4],#64-$rhotates[1][4]	// ?
	ror	$A[2][2],$A[2][3],#64-$rhotates[2][3]	// ?
	ror	$A[3][3],$A[3][2],#64-$rhotates[3][2]
	ror	$A[4][4],$A[4][1],#64-$rhotates[4][1]	// ?

	ror	$A[1][4],$A[4][2],#64-$rhotates[4][2]
	ror	$A[2][3],$A[3][4],#64-$rhotates[3][4]
	ror	$A[3][2],$A[2][1],#64-$rhotates[2][1]
	ror	$A[4][1],$A[1][3],#64-$rhotates[1][3]

	ror	$A[4][2],$A[2][4],#64-$rhotates[2][4]
	ror	$A[3][4],$A[4][3],#64-$rhotates[4][3]
	ror	$A[2][1],$A[1][2],#64-$rhotates[1][2]	// ?
	ror	$A[1][3],$A[3][1],#64-$rhotates[3][1]

	ror	$A[2][4],$A[4][0],#64-$rhotates[4][0]
	ror	$A[4][3],$A[3][0],#64-$rhotates[3][0]
	ror	$A[1][2],$A[2][0],#64-$rhotates[2][0]
	ror	$A[3][1],$A[1][0],#64-$rhotates[1][0]	// ?

	ror	$A[1][0],$C[0],#64-$rhotates[0][3]	// ?
	ror	$A[2][0],$C[3],#64-$rhotates[0][1]
	ror	$A[3][0],$C[2],#64-$rhotates[0][4]	// ?
	ror	$A[4][0],$C[1],#64-$rhotates[0][2]	// ?

	////////////////////////////////////////// Chi+Iota
	bic	$C[0],$A[0][2],$A[0][1]
	bic	$C[1],$A[0][3],$A[0][2]
	bic	$C[2],$A[0][0],$A[0][4]
	bic	$C[3],$A[0][1],$A[0][0]
	eor	$A[0][0],$A[0][0],$C[0]
	bic	$C[0],$A[0][4],$A[0][3]
	eor	$A[0][1],$A[0][1],$C[1]
	 ldr	c#$C[1],[csp,#16]
	eor	$A[0][3],$A[0][3],$C[2]
	eor	$A[0][4],$A[0][4],$C[3]
	eor	$A[0][2],$A[0][2],$C[0]
	 ldr	$C[3],[$C[1]],#8		// Iota[i++]

	bic	$C[0],$A[1][2],$A[1][1]
	 tst	$C[1],#255			// are we done?
	 str	c#$C[1],[csp,#16]
	bic	$C[1],$A[1][3],$A[1][2]
	bic	$C[2],$A[1][0],$A[1][4]
	 eor	$A[0][0],$A[0][0],$C[3]		// A[0][0] ^= Iota
	bic	$C[3],$A[1][1],$A[1][0]
	eor	$A[1][0],$A[1][0],$C[0]
	bic	$C[0],$A[1][4],$A[1][3]
	eor	$A[1][1],$A[1][1],$C[1]
	eor	$A[1][3],$A[1][3],$C[2]
	eor	$A[1][4],$A[1][4],$C[3]
	eor	$A[1][2],$A[1][2],$C[0]

	bic	$C[0],$A[2][2],$A[2][1]
	bic	$C[1],$A[2][3],$A[2][2]
	bic	$C[2],$A[2][0],$A[2][4]
	bic	$C[3],$A[2][1],$A[2][0]
	eor	$A[2][0],$A[2][0],$C[0]
	bic	$C[0],$A[2][4],$A[2][3]
	eor	$A[2][1],$A[2][1],$C[1]
	eor	$A[2][3],$A[2][3],$C[2]
	eor	$A[2][4],$A[2][4],$C[3]
	eor	$A[2][2],$A[2][2],$C[0]

	bic	$C[0],$A[3][2],$A[3][1]
	bic	$C[1],$A[3][3],$A[3][2]
	bic	$C[2],$A[3][0],$A[3][4]
	bic	$C[3],$A[3][1],$A[3][0]
	eor	$A[3][0],$A[3][0],$C[0]
	bic	$C[0],$A[3][4],$A[3][3]
	eor	$A[3][1],$A[3][1],$C[1]
	eor	$A[3][3],$A[3][3],$C[2]
	eor	$A[3][4],$A[3][4],$C[3]
	eor	$A[3][2],$A[3][2],$C[0]

	bic	$C[0],$A[4][2],$A[4][1]
	bic	$C[1],$A[4][3],$A[4][2]
	bic	$C[2],$A[4][0],$A[4][4]
	bic	$C[3],$A[4][1],$A[4][0]
	eor	$A[4][0],$A[4][0],$C[0]
	bic	$C[0],$A[4][4],$A[4][3]
	eor	$A[4][1],$A[4][1],$C[1]
	eor	$A[4][3],$A[4][3],$C[2]
	eor	$A[4][4],$A[4][4],$C[3]
	eor	$A[4][2],$A[4][2],$C[0]

	bne	.Loop

	ldr	c30,[csp,#16+__SIZEOF_POINTER__]
	.inst	0xd50323bf			// autiasp
	ret
.size	KeccakF1600_int,.-KeccakF1600_int

.type	KeccakF1600,%function
.align	5
KeccakF1600:
	.inst	0xd503233f			// paciasp
	stp	c29,c30,[csp,#-16*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]
	stp	c23,c24,[csp,#6*__SIZEOF_POINTER__]
	stp	c25,c26,[csp,#8*__SIZEOF_POINTER__]
	stp	c27,c28,[csp,#10*__SIZEOF_POINTER__]
	sub	csp,csp,#16+4*__SIZEOF_POINTER__

	str	c0,[csp,#16+2*__SIZEOF_POINTER__]	// offload argument
	mov	c#$C[0],c0
	ldp	$A[0][0],$A[0][1],[x0,#16*0]
	ldp	$A[0][2],$A[0][3],[$C[0],#16*1]
	ldp	$A[0][4],$A[1][0],[$C[0],#16*2]
	ldp	$A[1][1],$A[1][2],[$C[0],#16*3]
	ldp	$A[1][3],$A[1][4],[$C[0],#16*4]
	ldp	$A[2][0],$A[2][1],[$C[0],#16*5]
	ldp	$A[2][2],$A[2][3],[$C[0],#16*6]
	ldp	$A[2][4],$A[3][0],[$C[0],#16*7]
	ldp	$A[3][1],$A[3][2],[$C[0],#16*8]
	ldp	$A[3][3],$A[3][4],[$C[0],#16*9]
	ldp	$A[4][0],$A[4][1],[$C[0],#16*10]
	ldp	$A[4][2],$A[4][3],[$C[0],#16*11]
	ldr	$A[4][4],[$C[0],#16*12]

	adr	$C[2],iotas
	bl	KeccakF1600_int

	ldr	c#$C[0],[csp,#16+2*__SIZEOF_POINTER__]
	stp	$A[0][0],$A[0][1],[$C[0],#16*0]
	stp	$A[0][2],$A[0][3],[$C[0],#16*1]
	stp	$A[0][4],$A[1][0],[$C[0],#16*2]
	stp	$A[1][1],$A[1][2],[$C[0],#16*3]
	stp	$A[1][3],$A[1][4],[$C[0],#16*4]
	stp	$A[2][0],$A[2][1],[$C[0],#16*5]
	stp	$A[2][2],$A[2][3],[$C[0],#16*6]
	stp	$A[2][4],$A[3][0],[$C[0],#16*7]
	stp	$A[3][1],$A[3][2],[$C[0],#16*8]
	stp	$A[3][3],$A[3][4],[$C[0],#16*9]
	stp	$A[4][0],$A[4][1],[$C[0],#16*10]
	stp	$A[4][2],$A[4][3],[$C[0],#16*11]
	str	$A[4][4],[$C[0],#16*12]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	add	csp,csp,#16+4*__SIZEOF_POINTER__
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldp	c23,c24,[c29,#6*__SIZEOF_POINTER__]
	ldp	c25,c26,[c29,#8*__SIZEOF_POINTER__]
	ldp	c27,c28,[c29,#10*__SIZEOF_POINTER__]
	ldp	c29,c30,[csp],#16*__SIZEOF_POINTER__
	.inst	0xd50323bf			// autiasp
	ret
.size	KeccakF1600,.-KeccakF1600

.globl	SHA3_absorb
.type	SHA3_absorb,%function
.align	5
SHA3_absorb:
	.inst	0xd503233f			// paciasp
	stp	c29,c30,[csp,#-16*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]
	stp	c23,c24,[csp,#6*__SIZEOF_POINTER__]
	stp	c25,c26,[csp,#8*__SIZEOF_POINTER__]
	stp	c27,c28,[csp,#10*__SIZEOF_POINTER__]
	sub	csp,csp,#16+4*__SIZEOF_POINTER__+16

	stp	c0,c1,[csp,#16+2*__SIZEOF_POINTER__]	// offload arguments
	stp	x2,x3,[csp,#16+4*__SIZEOF_POINTER__]

	mov	c#$C[0],c0			// uint64_t A[5][5]
	mov	c#$C[1],c1			// const void *inp
	mov	$C[2],x2			// size_t len
	mov	$C[3],x3			// size_t bsz
	ldp	$A[0][0],$A[0][1],[$C[0],#16*0]
	ldp	$A[0][2],$A[0][3],[$C[0],#16*1]
	ldp	$A[0][4],$A[1][0],[$C[0],#16*2]
	ldp	$A[1][1],$A[1][2],[$C[0],#16*3]
	ldp	$A[1][3],$A[1][4],[$C[0],#16*4]
	ldp	$A[2][0],$A[2][1],[$C[0],#16*5]
	ldp	$A[2][2],$A[2][3],[$C[0],#16*6]
	ldp	$A[2][4],$A[3][0],[$C[0],#16*7]
	ldp	$A[3][1],$A[3][2],[$C[0],#16*8]
	ldp	$A[3][3],$A[3][4],[$C[0],#16*9]
	ldp	$A[4][0],$A[4][1],[$C[0],#16*10]
	ldp	$A[4][2],$A[4][3],[$C[0],#16*11]
	ldr	$A[4][4],[$C[0],#16*12]
	b	.Loop_absorb

.align	4
.Loop_absorb:
	subs	$C[0],$C[2],$C[3]		// len - bsz
	blo	.Labsorbed

	str	$C[0],[csp,#16+4*__SIZEOF_POINTER__]	// save len - bsz
	cmp	$C[3],#104
___
sub load_n_xor {
    my ($from,$to) = @_;

    for (my $i=$from; $i<=$to; $i++) {
$code.=<<___;
	ldr	$C[0],[$C[1],#`8*$i`]		// A[`$i/5`][`$i%5`] ^= *inp++
#ifdef	__AARCH64EB__
	rev	$C[0],$C[0]
#endif
	eor	$A[$i/5][$i%5],$A[$i/5][$i%5],$C[0]
___
    }
}
load_n_xor(0,8);
$code.=<<___;
	blo	.Lprocess_block

___
load_n_xor(9,12);
$code.=<<___;
	beq	.Lprocess_block

	cmp	$C[3],#144
___
load_n_xor(13,16);
$code.=<<___;
	blo	.Lprocess_block

___
load_n_xor(17,17);
$code.=<<___;
	beq	.Lprocess_block

___
load_n_xor(18,20);
$code.=<<___;

.Lprocess_block:
	add	c#$C[1],c#@C[1],@C[3]
	str	c#$C[1],[csp,#16+3*__SIZEOF_POINTER__]	// save inp

	adr	$C[2],iotas
	bl	KeccakF1600_int

	ldr	c#$C[1],[csp,#16+3*__SIZEOF_POINTER__]	// restore arguments
	ldp	$C[2],$C[3],[csp,#16+4*__SIZEOF_POINTER__]
	b	.Loop_absorb

.align	4
.Labsorbed:
	ldr	c#$C[1],[sp,#16+2*__SIZEOF_POINTER__]
	stp	$A[0][0],$A[0][1],[$C[1],#16*0]
	stp	$A[0][2],$A[0][3],[$C[1],#16*1]
	stp	$A[0][4],$A[1][0],[$C[1],#16*2]
	stp	$A[1][1],$A[1][2],[$C[1],#16*3]
	stp	$A[1][3],$A[1][4],[$C[1],#16*4]
	stp	$A[2][0],$A[2][1],[$C[1],#16*5]
	stp	$A[2][2],$A[2][3],[$C[1],#16*6]
	stp	$A[2][4],$A[3][0],[$C[1],#16*7]
	stp	$A[3][1],$A[3][2],[$C[1],#16*8]
	stp	$A[3][3],$A[3][4],[$C[1],#16*9]
	stp	$A[4][0],$A[4][1],[$C[1],#16*10]
	stp	$A[4][2],$A[4][3],[$C[1],#16*11]
	str	$A[4][4],[$C[1],#16*12]

	mov	x0,$C[2]			// return value
	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	add	csp,csp,#16+4*__SIZEOF_POINTER__+16
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldp	c23,c24,[c29,#6*__SIZEOF_POINTER__]
	ldp	c25,c26,[c29,#8*__SIZEOF_POINTER__]
	ldp	c27,c28,[c29,#10*__SIZEOF_POINTER__]
	ldp	c29,c30,[csp],#16*__SIZEOF_POINTER__
	.inst	0xd50323bf			// autiasp
	ret
.size	SHA3_absorb,.-SHA3_absorb
___
{
my ($A_flat,$out,$len,$bsz) = map("x$_",(19..22));
$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze,%function
.align	5
SHA3_squeeze:
	.inst	0xd503233f			// paciasp
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	cmov	$A_flat,x0			// put aside arguments
	cmov	$out,x1
	mov	$len,x2
	mov	$bsz,x3

.Loop_squeeze:
	ldr	x4,[x0],#8
	cmp	$len,#8
	blo	.Lsqueeze_tail
#ifdef	__AARCH64EB__
	rev	x4,x4
#endif
	str	x4,[$out],#8
	subs	$len,$len,#8
	beq	.Lsqueeze_done

	subs	x3,x3,#8
	bhi	.Loop_squeeze

	cmov	x0,$A_flat
	bl	KeccakF1600
	cmov	x0,$A_flat
	mov	x3,$bsz
	b	.Loop_squeeze

.align	4
.Lsqueeze_tail:
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done
	strb	w4,[$out],#1

.Lsqueeze_done:
	ldp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[csp,#4*__SIZEOF_POINTER__]
	ldp	c29,c30,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf			// autiasp
	ret
.size	SHA3_squeeze,.-SHA3_squeeze
___
}								}}}
								{{{
my @A = map([ "v".$_.".16b", "v".($_+1).".16b", "v".($_+2).".16b",
                             "v".($_+3).".16b", "v".($_+4).".16b" ],
            (0, 5, 10, 15, 20));

my @C = map("v$_.16b", (25..31));
my @D = @C[4,5,6,2,3];

$code.=<<___;
.type	KeccakF1600_ce,%function
.align	5
KeccakF1600_ce:
.Loop_ce:
	////////////////////////////////////////////////// Theta
	eor3	$C[0],$A[4][0],$A[3][0],$A[2][0]
	eor3	$C[1],$A[4][1],$A[3][1],$A[2][1]
	eor3	$C[2],$A[4][2],$A[3][2],$A[2][2]
	eor3	$C[3],$A[4][3],$A[3][3],$A[2][3]
	eor3	$C[4],$A[4][4],$A[3][4],$A[2][4]
	eor3	$C[0],$C[0],   $A[1][0],$A[0][0]
	eor3	$C[1],$C[1],   $A[1][1],$A[0][1]
	eor3	$C[2],$C[2],   $A[1][2],$A[0][2]
	eor3	$C[3],$C[3],   $A[1][3],$A[0][3]
	eor3	$C[4],$C[4],   $A[1][4],$A[0][4]

	rax1	$C[5],$C[0],$C[2]			// D[1]
	rax1	$C[6],$C[1],$C[3]			// D[2]
	rax1	$C[2],$C[2],$C[4]			// D[3]
	rax1	$C[3],$C[3],$C[0]			// D[4]
	rax1	$C[4],$C[4],$C[1]			// D[0]

	////////////////////////////////////////////////// Theta+Rho+Pi
	xar	$C[0],   $A[0][1],$D[1],#64-$rhotates[0][1] // C[0]=A[2][0]

	xar	$A[0][1],$A[1][1],$D[1],#64-$rhotates[1][1]
	xar	$A[1][1],$A[1][4],$D[4],#64-$rhotates[1][4]
	xar	$A[1][4],$A[4][2],$D[2],#64-$rhotates[4][2]
	xar	$A[4][2],$A[2][4],$D[4],#64-$rhotates[2][4]
	xar	$A[2][4],$A[4][0],$D[0],#64-$rhotates[4][0]

	xar	$C[1],   $A[0][2],$D[2],#64-$rhotates[0][2] // C[1]=A[4][0]

	xar	$A[0][2],$A[2][2],$D[2],#64-$rhotates[2][2]
	xar	$A[2][2],$A[2][3],$D[3],#64-$rhotates[2][3]
	xar	$A[2][3],$A[3][4],$D[4],#64-$rhotates[3][4]
	xar	$A[3][4],$A[4][3],$D[3],#64-$rhotates[4][3]
	xar	$A[4][3],$A[3][0],$D[0],#64-$rhotates[3][0]

	xar	$A[3][0],$A[0][4],$D[4],#64-$rhotates[0][4]

	xar	$D[4],   $A[4][4],$D[4],#64-$rhotates[4][4] // D[4]=A[0][4]
	xar	$A[4][4],$A[4][1],$D[1],#64-$rhotates[4][1]
	xar	$A[1][3],$A[1][3],$D[3],#64-$rhotates[1][3] // A[1][3]=A[4][1]
	xar	$A[0][4],$A[3][1],$D[1],#64-$rhotates[3][1] // A[0][4]=A[1][3]
	xar	$A[3][1],$A[1][0],$D[0],#64-$rhotates[1][0]

	xar	$A[1][0],$A[0][3],$D[3],#64-$rhotates[0][3]

	eor	$A[0][0],$A[0][0],$D[0]

	xar	$D[3],   $A[3][3],$D[3],#64-$rhotates[3][3] // D[3]=A[0][3]
	xar	$A[0][3],$A[3][2],$D[2],#64-$rhotates[3][2] // A[0][3]=A[3][3]
	xar	$D[1],   $A[2][1],$D[1],#64-$rhotates[2][1] // D[1]=A[3][2]
	xar	$D[2],   $A[1][2],$D[2],#64-$rhotates[1][2] // D[2]=A[2][1]
	xar	$D[0],   $A[2][0],$D[0],#64-$rhotates[2][0] // D[0]=A[1][2]

	////////////////////////////////////////////////// Chi+Iota
	bcax	$A[4][0],$C[1],   $A[4][2],$A[1][3]	// A[1][3]=A[4][1]
	bcax	$A[4][1],$A[1][3],$A[4][3],$A[4][2]	// A[1][3]=A[4][1]
	bcax	$A[4][2],$A[4][2],$A[4][4],$A[4][3]
	bcax	$A[4][3],$A[4][3],$C[1],   $A[4][4]
	bcax	$A[4][4],$A[4][4],$A[1][3],$C[1]	// A[1][3]=A[4][1]

	ld1r	{$C[1]},[x10],#8

	bcax	$A[3][2],$D[1],   $A[3][4],$A[0][3]	// A[0][3]=A[3][3]
	bcax	$A[3][3],$A[0][3],$A[3][0],$A[3][4]	// A[0][3]=A[3][3]
	bcax	$A[3][4],$A[3][4],$A[3][1],$A[3][0]
	bcax	$A[3][0],$A[3][0],$D[1],   $A[3][1]
	bcax	$A[3][1],$A[3][1],$A[0][3],$D[1]	// A[0][3]=A[3][3]

	bcax	$A[2][0],$C[0],   $A[2][2],$D[2]
	bcax	$A[2][1],$D[2],   $A[2][3],$A[2][2]
	bcax	$A[2][2],$A[2][2],$A[2][4],$A[2][3]
	bcax	$A[2][3],$A[2][3],$C[0],   $A[2][4]
	bcax	$A[2][4],$A[2][4],$D[2],   $C[0]

	bcax	$A[1][2],$D[0],   $A[1][4],$A[0][4]	// A[0][4]=A[1][3]
	bcax	$A[1][3],$A[0][4],$A[1][0],$A[1][4]	// A[0][4]=A[1][3]
	bcax	$A[1][4],$A[1][4],$A[1][1],$A[1][0]
	bcax	$A[1][0],$A[1][0],$D[0],   $A[1][1]
	bcax	$A[1][1],$A[1][1],$A[0][4],$D[0]	// A[0][4]=A[1][3]

	bcax	$A[0][3],$D[3],   $A[0][0],$D[4]
	bcax	$A[0][4],$D[4],   $A[0][1],$A[0][0]
	bcax	$A[0][0],$A[0][0],$A[0][2],$A[0][1]
	bcax	$A[0][1],$A[0][1],$D[3],   $A[0][2]
	bcax	$A[0][2],$A[0][2],$D[4],   $D[3]

	eor	$A[0][0],$A[0][0],$C[1]

	tst	x10,#255
	bne	.Loop_ce

	ret
.size	KeccakF1600_ce,.-KeccakF1600_ce

.type	KeccakF1600_cext,%function
.align	5
KeccakF1600_cext:
	.inst	0xd503233f		// paciasp
	stp	c29,c30,[csp,#-2*__SIZEOF_POINTER__-64]!
	add	c29,csp,#0
	stp	d8,d9,[csp,#2*__SIZEOF_POINTER__+0]	// per ABI requirement
	stp	d10,d11,[csp,#2*__SIZEOF_POINTER__+16]
	stp	d12,d13,[csp,#2*__SIZEOF_POINTER__+32]
	stp	d14,d15,[csp,#2*__SIZEOF_POINTER__+48]
___
for($i=0; $i<24; $i+=2) {		# load A[5][5]
my $j=$i+1;
$code.=<<___;
	ldp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	ldr	d24,[x0,#8*$i]
	adr	x10,iotas
	bl	KeccakF1600_ce
	ldr	c30,[csp,#__SIZEOF_POINTER__]
___
for($i=0; $i<24; $i+=2) {		# store A[5][5]
my $j=$i+1;
$code.=<<___;
	stp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	str	d24,[x0,#8*$i]

	ldp	d8,d9,[csp,#2*__SIZEOF_POINTER__+0]
	ldp	d10,d11,[csp,#2*__SIZEOF_POINTER__+16]
	ldp	d12,d13,[csp,#2*__SIZEOF_POINTER__+32]
	ldp	d14,d15,[csp,#2*__SIZEOF_POINTER__+48]
	ldr	c29,[csp],#2*__SIZEOF_POINTER__+64
	.inst	0xd50323bf		// autiasp
	ret
.size	KeccakF1600_cext,.-KeccakF1600_cext
___

{
my ($ctx,$inp,$len,$bsz) = map("x$_",(0..3));

$code.=<<___;
.globl	SHA3_absorb_cext
.type	SHA3_absorb_cext,%function
.align	5
SHA3_absorb_cext:
	.inst	0xd503233f		// paciasp
	stp	c29,c30,[csp,#-2*__SIZEOF_POINTER__-64]!
	add	c29,csp,#0
	stp	d8,d9,[csp,#2*__SIZEOF_POINTER__+0]	// per ABI requirement
	stp	d10,d11,[csp,#2*__SIZEOF_POINTER__+16]
	stp	d12,d13,[csp,#2*__SIZEOF_POINTER__+32]
	stp	d14,d15,[csp,#2*__SIZEOF_POINTER__+48]
___
for($i=0; $i<24; $i+=2) {		# load A[5][5]
my $j=$i+1;
$code.=<<___;
	ldp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	ldr	d24,[x0,#8*$i]
	b	.Loop_absorb_ce

.align	4
.Loop_absorb_ce:
	subs	$len,$len,$bsz		// len - bsz
	blo	.Labsorbed_ce

	cmp	$bsz,#104
___
sub load_n_xor_ce {
    my ($from,$to) = @_;
    my $range = $to-$from+1;

    while ($range>=4) {
$code.=<<___;
	ld1	{v27.8b-v30.8b},[$inp],#32
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v27.16b
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v28.16b
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v29.16b
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v30.16b
___
	$range-=4;
    }
    while ($range>=3) {
$code.=<<___;
	ld1	{v28.8b-v30.8b},[$inp],#24
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v28.16b
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v29.16b
	eor 	$A[$from/5][$from%5],$A[$from/5][$from++%5],v30.16b
___
	$range-=3;
    }
    while ($from<=$to) {
$code.=<<___;
	ld1	{v31.8b},[$inp],#8	// A[`$from/5`][`$from%5`] ^= *inp++
	eor	$A[$from/5][$from%5],$A[$from/5][$from++%5],v31.16b
___
    }
}
load_n_xor_ce(0,8);
$code.=<<___;
	blo	.Lprocess_block_ce

___
load_n_xor_ce(9,12);
$code.=<<___;
	beq	.Lprocess_block_ce

	cmp	$bsz,#144
___
load_n_xor_ce(13,16);
$code.=<<___;
	blo	.Lprocess_block_ce

___
load_n_xor_ce(17,17);
$code.=<<___;
	beq	.Lprocess_block_ce

___
load_n_xor_ce(18,20);
$code.=<<___;

.Lprocess_block_ce:
	adr	x10,iotas
	bl	KeccakF1600_ce

	b	.Loop_absorb_ce

.align	4
.Labsorbed_ce:
___
for($i=0; $i<24; $i+=2) {		# store A[5][5]
my $j=$i+1;
$code.=<<___;
	stp	d$i,d$j,[x0,#8*$i]
___
}
$code.=<<___;
	str	d24,[x0,#8*$i]
	add	x0,$len,$bsz		// return value

	ldp	d8,d9,[csp,#2*__SIZEOF_POINTER__+0]
	ldp	d10,d11,[csp,#2*__SIZEOF_POINTER__+16]
	ldp	d12,d13,[csp,#2*__SIZEOF_POINTER__+32]
	ldp	d14,d15,[csp,#2*__SIZEOF_POINTER__+48]
	ldp	c29,c30,[csp],#2*__SIZEOF_POINTER__+64
	.inst	0xd50323bf		// autiasp
	ret
.size	SHA3_absorb_cext,.-SHA3_absorb_cext
___
}
{
my ($ctx,$out,$len,$bsz) = map("x$_",(0..3));
$code.=<<___;
.globl	SHA3_squeeze_cext
.type	SHA3_squeeze_cext,%function
.align	5
SHA3_squeeze_cext:
	.inst	0xd503233f		// paciasp
	stp	c29,c30,[csp,#-2*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	cmov	x9,$ctx
	mov	x10,$bsz

.Loop_squeeze_ce:
	ldr	x4,[x9],#8
	cmp	$len,#8
	blo	.Lsqueeze_tail_ce
#ifdef	__AARCH64EB__
	rev	x4,x4
#endif
	str	x4,[$out],#8
	beq	.Lsqueeze_done_ce

	sub	$len,$len,#8
	subs	x10,x10,#8
	bhi	.Loop_squeeze_ce

	bl	KeccakF1600_cext
	ldr	c30,[csp,#__SIZEOF_POINTER__]
	cmov	x9,$ctx
	mov	x10,$bsz
	b	.Loop_squeeze_ce

.align	4
.Lsqueeze_tail_ce:
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1
	lsr	x4,x4,#8
	subs	$len,$len,#1
	beq	.Lsqueeze_done_ce
	strb	w4,[$out],#1

.Lsqueeze_done_ce:
	ldr	c29,[csp],#2*__SIZEOF_POINTER__
	.inst	0xd50323bf		// autiasp
	ret
.size	SHA3_squeeze_cext,.-SHA3_squeeze_cext
___
}								}}}
$code.=<<___;
.asciz	"Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by \@dot-asm"
___

{   my  %opcode = (
	"rax1"	=> 0xce608c00,	"eor3"	=> 0xce000000,
	"bcax"	=> 0xce200000,	"xar"	=> 0xce800000	);

    sub unsha3 {
	my ($mnemonic,$arg)=@_;

	$arg =~ m/[qv]([0-9]+)[^,]*,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv#]([0-9\-]+))?)?/
	&&
	sprintf ".inst\t0x%08x\t//%s %s",
			$opcode{$mnemonic}|$1|($2<<5)|($3<<16)|(eval($4)<<10),
			$mnemonic,$arg;
    }
}

foreach(split("\n",$code)) {
	use integer;

	s/\`([^\`]*)\`/eval($1)/ge;

	m/\b(ld1r|rax1|xar)\b/ and s/\.16b/.2d/g;
	$sha3ops or s/\b(eor3|rax1|xar|bcax)\s+(v.*)/unsha3($1,$2)/ge;
	s/([cw])#x([0-9]+)/$1$2/g;

	print $_,"\n";
}

close STDOUT;
