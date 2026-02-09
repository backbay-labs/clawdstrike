#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm.
# ====================================================================
#
# X25519 lower-level primitives for ARMv8.
#
# These are base 2^64 multiplication, squaring, addition, subtraction
# operating modulo 2^256-38, along with final reduction tying final
# result modulo 2^255-19.
#
#		ECDH improvement vs. 2^51 gcc 5.4
#
# Apple-A7	+16%
# Cortex-A53	+22%
# Cortex-A57	+21%(*)
# X-Gene	+21%
# Denver	+12%
# Mongoose	+23%
# ThunderX2	+22%
#
# (*)	unlike on other processors, base 2^51 is not actually faster
#	than base 2^25.5 on Cortex-A57, it's ~15% slower, so that
#	overall, base 2^64 is only nominally faster than best option
#	for this processor;

$flavour=shift;
$output=shift;

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

my ($rp,$ap,$bp,$bi,$a0,$a1,$a2,$a3,$t0,$t1,$t2,$t3,
    $acc0,$acc1,$acc2,$acc3,$acc4,$acc5) =
    map("x$_",(0..17));

my ($acc6,$acc7) = ($bp,$ap);

$code.=<<___;
.text

.globl	x25519_fe64_mul
.type	x25519_fe64_mul,%function
.align	4
x25519_fe64_mul:
	ldr	$bi,[$bp],#8
	ldp	$a0,$a1,[$ap,#0]
	ldp	$a2,$a3,[$ap,#16]

	mul	$acc0,$a0,$bi		// a[0]*b[0]
	ldr	$ap,[$bp],#8
	umulh	$t0,$a0,$bi
	mul	$acc1,$a1,$bi		// a[1]*b[0]
	umulh	$t1,$a1,$bi
	mul	$acc2,$a2,$bi		// a[2]*b[0]
	umulh	$t2,$a2,$bi
	mul	$acc3,$a3,$bi		// a[3]*b[0]
	umulh	$t3,$a3,$bi
___
for(my @acc=($acc0,$acc1,$acc2,$acc3,$acc4,$acc5,$acc6,$acc7),
    my ($bi,$ap)=($ap,$bi),
    my $i=1; $i<4; $i++) {
my $acc4 = $i==1? "xzr" : @acc[4];

$code.=<<___	if ($i<3);
	ldr	$ap,[$bp],#8
___
$code.=<<___	if ($i==3);
	mov	$ap,#38
___
$code.=<<___;
	adds	@acc[1],@acc[1],$t0	// accumulate high parts
	mul	$t0,$a0,$bi
	adcs	@acc[2],@acc[2],$t1
	mul	$t1,$a1,$bi
	adcs	@acc[3],@acc[3],$t2
	mul	$t2,$a2,$bi
	adc	@acc[4],$acc4,$t3
	mul	$t3,$a3,$bi
	adds	@acc[1],@acc[1],$t0	// accumulate low parts
	umulh	$t0,$a0,$bi
	adcs	@acc[2],@acc[2],$t1
	umulh	$t1,$a1,$bi
	adcs	@acc[3],@acc[3],$t2
	umulh	$t2,$a2,$bi
	adcs	@acc[4],@acc[4],$t3
	umulh	$t3,$a3,$bi
	adc	@acc[5],xzr,xzr
___
	shift(@acc);
	($bi,$ap)=($ap,$bi);
}
$code.=<<___;
	 adds	$acc4,$acc4,$t0		// accumulate high parts
	 adcs	$acc5,$acc5,$t1
	mul	$t0,$acc4,$bi		// reduce
	 adcs	$acc6,$acc6,$t2
	mul	$t1,$acc5,$bi
	 adc	$acc7,$acc7,$t3
	mul	$t2,$acc6,$bi
	adds	$acc0,$acc0,$t0
	mul	$t3,$acc7,$bi
	adcs	$acc1,$acc1,$t1
	umulh	$t0,$acc4,$bi
	adcs	$acc2,$acc2,$t2
	umulh	$t1,$acc5,$bi
	adcs	$acc3,$acc3,$t3
	umulh	$t2,$acc6,$bi
	adc	$acc4,xzr,xzr
	umulh	$t3,$acc7,$bi

	adds	$acc1,$acc1,$t0
	adcs	$acc2,$acc2,$t1
	adcs	$acc3,$acc3,$t2
	adc	$acc4,$acc4,$t3

	mul	w#$acc4,w#$acc4,w#$bi	// 32-bit multiplication is sufficient

	adds	$acc0,$acc0,$acc4
	adcs	$acc1,$acc1,xzr
	adcs	$acc2,$acc2,xzr
	adcs	$acc3,$acc3,xzr

	add	$acc4,$acc0,#38
	csel	$acc0,$acc4,$acc0,cs	// carry ? $acc0+38 : $acc0

	stp	$acc2,$acc3,[$rp,#16]
	stp	$acc0,$acc1,[$rp,#0]

	ret
.size	x25519_fe64_mul,.-x25519_fe64_mul

.globl	x25519_fe64_sqr
.type	x25519_fe64_sqr,%function
.align	4
x25519_fe64_sqr:
	ldp	$a0,$a1,[$ap,#0]
	ldp	$a2,$a3,[$ap,#16]

	////////////////////////////////////////////////////////////////
	//  |  |  |  |  |  |a1*a0|  |
	//  |  |  |  |  |a2*a0|  |  |
	//  |  |a3*a2|a3*a0|  |  |  |
	//  |  |  |  |a2*a1|  |  |  |
	//  |  |  |a3*a1|  |  |  |  |
	// *|  |  |  |  |  |  |  | 2|
	// +|a3*a3|a2*a2|a1*a1|a0*a0|
	//  |--+--+--+--+--+--+--+--|
	//  |A7|A6|A5|A4|A3|A2|A1|A0|, where Ax is $accx, i.e. follow $accx
	//
	//  "can't overflow" below mark carrying into high part of
	//  multiplication result, which can't overflow, because it
	//  can never be all ones.

	mul	$acc1,$a1,$a0		// a[1]*a[0]
	umulh	$t1,$a1,$a0
	mul	$acc2,$a2,$a0		// a[2]*a[0]
	umulh	$t2,$a2,$a0
	mul	$acc3,$a3,$a0		// a[3]*a[0]
	umulh	$acc4,$a3,$a0

	adds	$acc2,$acc2,$t1		// accumulate high parts of multiplication
	 mul	$t0,$a2,$a1		// a[2]*a[1]
	 umulh	$t1,$a2,$a1
	adcs	$acc3,$acc3,$t2
	 mul	$t2,$a3,$a1		// a[3]*a[1]
	 umulh	$t3,$a3,$a1
	adc	$acc4,$acc4,xzr		// can't overflow

	mul	$acc5,$a3,$a2		// a[3]*a[2]
	umulh	$acc6,$a3,$a2

	adds	$t1,$t1,$t2		// accumulate high parts of multiplication
	 mul	$acc0,$a0,$a0		// a[0]*a[0]
	adc	$t2,$t3,xzr		// can't overflow

	adds	$acc3,$acc3,$t0		// accumulate low parts of multiplication
	 umulh	$a0,$a0,$a0
	adcs	$acc4,$acc4,$t1
	 mul	$t1,$a1,$a1		// a[1]*a[1]
	adcs	$acc5,$acc5,$t2
	 umulh	$a1,$a1,$a1
	adc	$acc6,$acc6,xzr		// can't overflow

	adds	$acc1,$acc1,$acc1	// acc[1-6]*=2
	 mul	$t2,$a2,$a2		// a[2]*a[2]
	adcs	$acc2,$acc2,$acc2
	 umulh	$a2,$a2,$a2
	adcs	$acc3,$acc3,$acc3
	 mul	$t3,$a3,$a3		// a[3]*a[3]
	adcs	$acc4,$acc4,$acc4
	 umulh	$a3,$a3,$a3
	adcs	$acc5,$acc5,$acc5
	 mov	$bi,#38
	adcs	$acc6,$acc6,$acc6
	adc	$acc7,xzr,xzr

	 adds	$acc1,$acc1,$a0		// +a[i]*a[i]
	 adcs	$acc2,$acc2,$t1
	 adcs	$acc3,$acc3,$a1
	 adcs	$acc4,$acc4,$t2
	 adcs	$acc5,$acc5,$a2
	mul	$t0,$acc4,$bi		// reduce
	 adcs	$acc6,$acc6,$t3
	mul	$t1,$acc5,$bi
	 adc	$acc7,$acc7,$a3
	mul	$t2,$acc6,$bi
	adds	$acc0,$acc0,$t0
	mul	$t3,$acc7,$bi
	adcs	$acc1,$acc1,$t1
	umulh	$t0,$acc4,$bi
	adcs	$acc2,$acc2,$t2
	umulh	$t1,$acc5,$bi
	adcs	$acc3,$acc3,$t3
	umulh	$t2,$acc6,$bi
	adc	$acc4,xzr,xzr
	umulh	$t3,$acc7,$bi

	adds	$acc1,$acc1,$t0
	adcs	$acc2,$acc2,$t1
	adcs	$acc3,$acc3,$t2
	adc	$acc4,$acc4,$t3

	mul	w#$acc4,w#$acc4,w#$bi	// 32-bit multiplication is sufficient

	adds	$acc0,$acc0,$acc4
	adcs	$acc1,$acc1,xzr
	adcs	$acc2,$acc2,xzr
	adcs	$acc3,$acc3,xzr

	add	$acc4,$acc0,#38
	csel	$acc0,$acc4,$acc0,cs	// carry ? $acc0+38 : $acc0

	stp	$acc2,$acc3,[$rp,#16]
	stp	$acc0,$acc1,[$rp,#0]

	ret
.size	x25519_fe64_sqr,.-x25519_fe64_sqr

.globl	x25519_fe64_mul121666
.type	x25519_fe64_mul121666,%function
.align	4
x25519_fe64_mul121666:
	mov	$bi,#(121666-65536)
	movk	$bi,#1,lsl#16		// +65536
	ldp	$t0,$t1,[$ap,#0]
	ldp	$t2,$t3,[$ap,#16]

	mul	$acc0,$t0,$bi
	umulh	$t0,  $t0,$bi
	mul	$acc1,$t1,$bi
	umulh	$t1,  $t1,$bi
	mul	$acc2,$t2,$bi
	umulh	$t2,  $t2,$bi
	mul	$acc3,$t3,$bi
	umulh	$t3,  $t3,$bi

	adds	$acc1,$acc1,$t0
	mov	$bi,#38
	adcs	$acc2,$acc2,$t1
	adcs	$acc3,$acc3,$t2
	adc	$acc4,xzr,  $t3

	mul	w#$acc4,w#$acc4,w#$bi	// 32-bit multiplication is sufficient

	adds	$acc0,$acc0,$acc4
	adcs	$acc1,$acc1,xzr
	adcs	$acc2,$acc2,xzr
	adcs	$acc3,$acc3,xzr

	add	$acc4,$acc0,#38
	csel	$acc0,$acc4,$acc0,cs	// carry ? $acc0+38 : $acc0

	stp	$acc2,$acc3,[$rp,#16]
	stp	$acc0,$acc1,[$rp,#0]

	ret
.size	x25519_fe64_mul121666,.-x25519_fe64_mul121666

.globl	x25519_fe64_add
.type	x25519_fe64_add,%function
.align	4
x25519_fe64_add:
	ldp	$acc0,$acc1,[$ap,#0]
	ldp	$t0,  $t1,  [$bp,#0]
	ldp	$acc2,$acc3,[$ap,#16]

	adds	$acc0,$acc0,$t0
	ldp	$t2,  $t3,  [$bp,#16]
	adcs	$acc1,$acc1,$t1
	mov	$acc4,#38
	adcs	$acc2,$acc2,$t2
	adcs	$acc3,$acc3,$t3

	csel	$acc4,$acc4,xzr,cs	// carry*38

	adds	$acc0,$acc0,$acc4
	adcs	$acc1,$acc1,xzr
	adcs	$acc2,$acc2,xzr
	adcs	$acc3,$acc3,xzr

	add	$acc4,$acc0,#38
	csel	$acc0,$acc4,$acc0,cs	// carry ? $acc0+38 : $acc0

	stp	$acc2,$acc3,[$rp,#16]
	stp	$acc0,$acc1,[$rp,#0]

	ret
.size	x25519_fe64_add,.-x25519_fe64_add

.globl	x25519_fe64_sub
.type	x25519_fe64_sub,%function
.align	4
x25519_fe64_sub:
	ldp	$acc0,$acc1,[$ap,#0]
	ldp	$t0,  $t1,  [$bp,#0]
	ldp	$acc2,$acc3,[$ap,#16]

	subs	$acc0,$acc0,$t0
	ldp	$t2,  $t3,  [$bp,#16]
	sbcs	$acc1,$acc1,$t1
	mov	$acc4,#38
	sbcs	$acc2,$acc2,$t2
	sbcs	$acc3,$acc3,$t3

	csel	$acc4,$acc4,xzr,cc	// borrow*38

	subs	$acc0,$acc0,$acc4
	sbcs	$acc1,$acc1,xzr
	sbcs	$acc2,$acc2,xzr
	sbcs	$acc3,$acc3,xzr

	sub	$acc4,$acc0,#38
	csel	$acc0,$acc4,$acc0,cc	// borrow ? $acc0-38 : $acc0

	stp	$acc2,$acc3,[$rp,#16]
	stp	$acc0,$acc1,[$rp,#0]

	ret
.size	x25519_fe64_sub,.-x25519_fe64_sub

.globl	x25519_fe64_tobytes
.type	x25519_fe64_tobytes,%function
.align	4
x25519_fe64_tobytes:
	ldp	$acc2,$acc3,[$ap,#16]
	ldp	$acc0,$acc1,[$ap,#0]

	asr	$acc4,$acc3,#63		// most significant bit -> mask
	mov	$t0,#19
	and	$acc4,$acc4,$t0
	add	$acc4,$acc4,$t0		// compare to modulus in the same go

	adds	$acc0,$acc0,$acc4
	lsl	$acc3,$acc3,#1
	adcs	$acc1,$acc1,xzr
	lsr	$acc3,$acc3,#1		// most significant bit cleared
	adcs	$acc2,$acc2,xzr
	adc	$acc3,$acc3,xzr

	asr	$acc4,$acc3,#63		// most significant bit -> mask
	lsl	$acc3,$acc3,#1
	bic	$acc4,$t0,$acc4
	lsr	$acc3,$acc3,#1		// most significant bit cleared

	subs	$acc0,$acc0,$acc4
	sbcs	$acc1,$acc1,xzr
	sbcs	$acc2,$acc2,xzr
	sbc	$acc3,$acc3,xzr
#ifdef	__AARCH64EB__
	rev	$acc0,$acc0
	rev	$acc1,$acc1
	rev	$acc2,$acc2
	rev	$acc3,$acc3
#endif
	stp	$acc0,$acc1,[$rp,#0]
	stp	$acc2,$acc3,[$rp,#16]

	ret
.size	x25519_fe64_tobytes,.-x25519_fe64_tobytes

// These are never called, but can be needed at link time, more
// specifically in case compiler doesn't delete dead code.
.globl	x25519_fe51_mul
.globl	x25519_fe51_mul121666
.globl	x25519_fe51_sqr
x25519_fe51_mul:
x25519_fe51_mul121666:
x25519_fe51_sqr:
	.inst	0
	ret
.asciz	"X25519 primitives for ARMv8, CRYPTOGAMS by \@dot-asm"
___

$code=~s/w#x/w/g;

print $code;
close STDOUT;
