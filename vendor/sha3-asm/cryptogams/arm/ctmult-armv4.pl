#!/usr/bin/env perl
#
# Problem with ARM32 multiplier is two-fold. Thumb-1 instruction set
# doesn't specify widening 32x32=64-bit multiplication instruction. As
# result '(unsigned long long)a * b' is compiled as a call to a library
# subroutine with unspecified constant-time properties. Secondly, some
# microcontrollers have non-constant-time multiplier. In other words,
# whenever you find yourself targeting Thumb-1, such as Cortex-M0/1, or
# processor with non-constant-time multiplier, replace multiplications
# with calls to ct_umull and pass -DCT_UMULL to the compiler when
# assembling this module. The macro engages a slower code path that
# performs multiplications with fixed-width operands. Well, not quite,
# it's assumed that the target Thumb-1 processor multiplies 17- and
# 18-bit values in the same amount of cycles...
#
# It would be possible to simplify the const-ification if we knew which
# of the two multiplicands incurs the execution time variation.

$flavour = shift;
if ($flavour=~/\w[\w\-]*\.\w+$/) { $output=$flavour; undef $flavour; }
else { while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {} }

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

$code.=<<___;
#ifndef	__ARMEB__
# define LO r0
# define HI r1
#else
# define LO r1
# define HI r0
#endif

.text

#if defined(__thumb2__) || defined(__ARM_ARCH_ISA_ARM)

# if defined(__thumb2__)
.syntax unified
.thumb
# else
.code	32
# endif

.globl	ct_umull
.type	ct_umull, %function
ct_umull:
# ifdef	CT_UMULL		// work around non-constant-time multiplier
	bic	r2, r1, r0, asr#31
	bic	r3, r0, r1, asr#31
	add	r3, r3, r2

	orr	r2, r0, #1<<31
	orrs	r0, r0, r1
	orr	r1, r1, #1<<31
	umull	LO, HI, r2, r1
	it	pl
	subpl	HI, HI, #1<<30
	subs	LO, LO, r3, lsl#31
	sbc	HI, HI, r3, lsr#1
# else
	mov	r2, r0
	umull	LO, HI, r2, r1
# endif
# if	__ARM_ARCH<5 && !defined(__thumb__)
	tst	lr, #1
	moveq	pc, lr
	.inst	0xe12fff1e	@ bx lr
# else
	bx	lr
# endif
.size	ct_umull, .-ct_umull

#else				// Thumb-1 code path

.syntax	unified
.code	16

.globl	ct_umull
.type	ct_umull, %function
ct_umull:
# ifdef	CT_UMULL		// work around non-constant-time multiplier
	movs	r3, #1
	negs	r3, r3
	push	{r4-r7}
	lsrs	r6, r3, #16	@ #0xffff

	@ break down inputs to 16-bit pairs
	lsrs	r5, r0, #16	@ x1 = x>>16
	ands	r0, r6		@ x0 = x&0xffff
	movs	r3, #1
	lsrs	r7, r1, #16	@ y1 = y>>16
	ands	r6, r1		@ y0 = y&0xffff
	lsls	r3, r3, #17	@ #1<<17

	@ calculate the "low" term
	adds	r1, r0, r6
	adds	r4, r0, r3	@ #1<<17
	adds	r2, r6, r3	@ #1<<17
	muls	r2, r4
	lsls	r1, r1, #17
	 subs	r4, r0, r5	@ x0-x1
	subs	r0, r2, r1	@ x0*y0

	@ calculate the "high" term
	adds	r1, r5, r7
	adds	r5, r5, r3	@ #1<<17
	adds	r2, r7, r3	@ #1<<17
	muls	r2, r5
	lsls	r1, r1, #17
	 subs	r6, r7, r6	@ y1-y0
	subs	r2, r2, r1	@ x1*y1

	@ calculate the "middle" term with Karatsuba algorithm
	movs	r7, r4
	eors	r7, r6		@ record the sign
	adds	r1, r4, r6
	adds	r4, r4, r3	@ #1<<17
	adds	r6, r6, r3	@ #1<<17
	muls	r6, r4
	lsls	r1, r1, #17
	asrs	r7, r7, #31
	subs	r6, r6, r1	@ (x0-x1)*(y1-y0)

	negs	r3, r6
	orrs	r3, r6
	 movs	r5, #0
	asrs	r3, r3, #31
	ands	r7, r3		@ [subs r6, r6, r1;] moveq r7, #0

	adds	r6, r6, r0
	adcs	r7, r5
	adds	r6, r6, r2
	adcs	r7, r5		@ (x0-x1)*(y1-y0) + x0*y0 + x1*y1

	@ accumulate the "middle" term
	lsls	r5, r6, #16
	lsrs	r6, r6, #16
	lsls	r7, r7, #16
	adds	LO, r0, r5
	adcs	r2, r6
	adds	HI, r2, r7

	pop	{r4-r7}
# else				// straightforward widening multiplication
	movs	r3, #1
	negs	r3, r3
	push	{r4-r5}
	lsrs	r4, r3, #16	@ #0xffff

	@ break down inputs to 16-bit pairs
	lsrs	r3, r0, #16	@ x1 = x>>16
	ands	r0, r4		@ x0 = x&0xffff
	lsrs	r5, r1, #16	@ y1 = y>>16
	ands	r4, r1		@ y0 = y&0xffff

	movs	r1, r0
	muls	r0, r4		@ x0*y0
	muls	r4, r3		@ y0*x1
	muls	r3, r5		@ x1*y1
	muls	r5, r1		@ y1*x0

	@ calculate the "middle" term
	movs	r2, #0
	adds	r4, r4, r5
	adcs	r2, r2

	@ accumulate the "middle" term
	lsls	r1, r4, #16
	lsrs	r4, r4, #16
	lsls	r2, r2, #16
	adds	LO, r0, r1
	adcs	r3, r4
	adds	HI, r2, r3

	pop	{r4-r5}
# endif
	bx	lr
.size	ct_umull, .-ct_umull
#endif
___

print $code;
close STDOUT; # enforce flush
