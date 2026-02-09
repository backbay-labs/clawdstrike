#!/usr/bin/env perl
#
# If your target processor doesn't have a constant-time multiplier,
# or doesn't have multiplier [denoted by __riscv_mul being undefined],
# replace '(unsigned long long)a * b' with a call to ct_umull. The
# challenge specific to RISC-V is that 32-bit widening multiplication
# is performed with a pair of instructions, one of which being
# sign-agnostic. Which means that setting most significant bits is
# not sufficient to mitigate the timing variations. Instead we clear
# the most significant bit and add the second most significant bit,
# and assume that 31- and 32-bit values are multiplied in the same
# amount of cycles.
#
# It would be possible to simplify the const-ification if we knew which
# of the two multiplicands incurs the execution time variation.
#
######################################################################
($zero,$ra,$sp,$gp,$tp)=map("x$_",(0..4));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7,28..31));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
######################################################################

$flavour = shift || "64";

for (@ARGV) {   $output=$_ if (/\w[\w\-]*\.\w+$/);   }
open STDOUT,">$output";

$code=<<___;
.option	pic
.text

.globl	ct_umull
.type	ct_umull, \@function
.align	4
ct_umull:
___
$code.=<<___	if ($flavour =~ /64/);
#ifdef	__riscv_mul
	li	$t0, -1
	li	$t1, 3
	srl	$t0, $t0, 32		# 0xffffffff
	sll	$t1, $t1, 32		# 0x300000000
	and	$a0, $a0, $t0		# arguments are passed sign-extended,
	and	$a1, $a1, $t0		# so clear the upper 32 bits.

	add	$a2, $a0, $a1
	or	$a0, $a0, $t1
	or	$a1, $a1, $t1

	sll	$a3, $a2, 33
	sll	$a2, $a2, 32

	mul	$a0, $a0, $a1

	add	$a2, $a2, $a3		# (3*(a+b))<<32
	sub	$a0, $a0, $a2
#else				// no multiplier, just shift-n-conditional-add
	sll	$a2, $a0, 32
	li	$a0, 0
	li	$t1, 32
.Loop:
	sraw	$t0, $a1, 31
	srl	$a2, $a2, 1
	addi	$t1, $t1, -1
	and	$t0, $t0, $a2
	sllw	$a1, $a1, 1
	add	$a0, $a0, $t0
	bnez	$t1, .Loop
#endif
___
$code.=<<___	if ($flavour =~ /32/);
#if __riscv_xlen == 32
# define MULX(hi,lo,a,b)	mulhu hi,a,b; mul lo,a,b
# define srlw	srl
# define sraw	sra
# define sllw	sll
# define addw	add
# define subw	sub
#else
# define MULX(hi,lo,a,b)	mul hi,a,b; addiw lo,hi,0; srai hi,hi,32
#endif
#ifdef	__riscv_mul
	lui	$t0, 0x80000
	lui	$t1, 0x40000	# 0x40000000
	addw	$t0, $t0, -1	# 0x7fffffff
	sraw	$a2, $a0, 31
	sraw	$a3, $a1, 31
	and	$a4, $a1, $a2	# |b| times |a|'s msb
	and	$a5, $a0, $a3	# |a| times |b|'s msb
	and	$a0, $a0, $t0	# |a|&0x7fffffff
	and	$a1, $a1, $t0	# |b|&0x7fffffff

	and	$a3, $a3, $a2	# product of the most significant bits
	add	$a2, $a0, $a1	# |a|&0x7fffffff + |b|&0x7fffffff
	add	$a0, $a0, $t1	# |a|&0x7fffffff + 0x40000000
	add	$a1, $a1, $t1	# |b|&0x7fffffff + 0x40000000

	MULX($a7, $a6, $a0, $a1)

	sllw	$a1, $a2, 30	# (|a|&0x7fffffff + |b|&0x7fffffff)<<30
	srlw	$a2, $a2, 2

	lui	$t0, 0x10000	# 0x10000000
	addw	$a5, $a5, $a4	# sum of the cross-msb products
	addw	$a2, $a2, $t0	# account for 0x40000000**2
	and	$a3, $a3, $t1	# product of the most significant bits as bit

	# subtract the excess term resulting from addition of 0x40000000
	sltu	$t0, $a6, $a1	# borrow
	subw	$a6, $a6, $a1
	subw	$a7, $a7, $a2
	subw	$a3, $a3, $t0	# tuck away the borrow

	# add the missing term resulting from masking the most significant bits
	sllw	$a4, $a5, 31	# (sum of the cross-msb products)<<31
	srlw	$a5, $a5, 1
	addw	$a0, $a6, $a4
	addw	$a1, $a7, $a5
	sltu	$a4, $a0, $a4	# carry
	addw	$a1, $a1, $a3
	addw	$a1, $a1, $a4
#else				// no multiplier, just shift-n-conditional-add
	sraw	$t0, $a0, 31
	sllw	$a2, $a0, 1
	and	$a4, $a1, $t0
	mv	$a3, $a1
	sllw	$a0, $a4, 31
	srlw	$a1, $a4, 1
	li	$t1, 30
	li	$t2, 1
.Loop:
	sraw	$t0, $a2, 31
	sllw	$a2, $a2, 1
	and	$a4, $a3, $t0
	addi	$t2, $t2, 1
	sllw	$a5, $a4, $t1
	srlw	$a6, $a4, $t2
	addw	$a0, $a0, $a5
	addw	$a1, $a1, $a6
	sltu	$a5, $a0, $a5
	addi	$t1, $t1, -1
	addw	$a1, $a1, $a5
	bnez	$t1, .Loop

	sraw	$t0, $a2, 31
	and	$a4, $a3, $t0
	addw	$a0, $a0, $a4
	sltu	$a5, $a0, $a4
	addw	$a1, $a1, $a5
#endif
#if __riscv_xlen == 64
	sll	$a0, $a0, 32
	sll	$a1, $a1, 32
	srl	$a0, $a0, 32
	or	$a0, $a0, $a1
#endif
___
$code.=<<___;
#ifndef	__CHERI_PURE_CAPABILITY__
	ret
#else
	cret
#endif
.size	ct_umull,.-ct_umull
___

print $code;
close STDOUT;
