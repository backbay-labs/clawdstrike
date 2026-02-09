#!/usr/bin/env perl
#
# If your target processor doesn't have a constant-time multiplier,
# replace '(unsigned long long)a * b' with a call to ct_umull. The
# challenge specific to PPC is that 32-bit widening multiplication
# is performed with a pair of instructions, one of which being
# sign-agnostic. This means that setting most significant bits is
# not sufficient to mitigate the timing variations. Instead we clear
# the most significant bit and add the second most significant bit,
# and assume that 31- and 32-bit values are multiplied in the same
# amount of cycles.
#
# It would be possible to simplify the const-ification if we knew which
# of the two multiplicands incurs the execution time variation.

$flavour = shift;

die "nonsense $flavour" if ($flavour !~ /(64|32)/);

# Define endianness based on flavour
# i.e.: linux64le
($LO, $HI) = ($flavour=~/le$/) ? ("r3", "r4") : ("r4", "r3");

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour ".shift || die "can't call $xlate: $!";

$code=<<___;
.machine	"any"
.text

.globl	.ct_umull
.align	4
.ct_umull:
___
$code.=<<___	if ($flavour =~ /64/);	# is there one with non-ct multiplier?
	li	r0, 3
	sldi	r0, r0, 32		# 0x300000000
	add	r5, r3, r4
	or	r3, r3, r0
	or	r4, r4, r0

	sldi	r6, r5, 33
	sldi	r5, r5, 32

	mulld	r3, r3, r4

	add	r5, r5, r6		# (3*(a+b))<<32
	sub	r3, r3, r5		# subtract the excess term
___
$code.=<<___	if ($flavour =~ /32/);
	lis	r0, 0x7fff
	srawi	r5, r3, 31
	srawi	r6, r4, 31
	ori	r0, r0, 0xffff		# 0x7fffffff
	and	r7, r4, r5		# |b| times |a|'s msb
	and	r8, r3, r6		# |a| times |b|'s msb
	and	r3, r3, r0		# |a|&0x7fffffff
	and	r4, r4, r0		# |b|&0x7fffffff

	and	r6, r6, r5		# product of the most significant bits
	add	r5, r3, r4		# |a|&0x7fffffff + |b|&0x7fffffff
	addis	r3, r3, 0x4000		# |a|&0x7fffffff + 0x40000000
	addis	r4, r4, 0x4000		# |b|&0x7fffffff + 0x40000000

	andis.	r6, r6, 0x4000
	add	r8, r8, r7		# sum of the cross-msb products

	mulhwu	r10, r3, r4
	mullw	r9,  r3, r4

	# subtract the excess term resulting from addition of 0x40000000
	slwi	r3, r5, 30		# (|a|&0x7fffffff + |b|&0x7fffffff)<<30
	srwi	r4, r5, 2
	subis	r10, r10, 0x1000	# subtract 0x40000000**2
	subfc	r9,  r3, r9
	subfe	r10, r4, r10

	# add the missing term resulting from masking the most significant bits
	slwi	r7, r8, 31		# (sum of the cross-msb products)<<31
	srwi	r8, r8, 1
	add	r10, r6, r10
	addc	$LO, r7, r9
	adde	$HI, r8, r10
___
$code.=<<___;
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,2,0
.size	.ct_umull,.-.ct_umull
___

print $code;
close STDOUT;
