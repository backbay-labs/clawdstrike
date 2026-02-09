#!/usr/bin/env perl
#
# If your target processor doesn't have a constant-time multiplier,
# replace '(unsigned long long)a * b' with a call to ct_umull.
#
# It would be possible to simplify the const-ification if we knew which
# of the two multiplicands incurs the execution time variation.
#
######################################################################
# There is a number of MIPS ABI in use, O32 and N32/64 are most
# widely used. Then there is a new contender: NUBI. It appears that if
# one picks the latter, it's possible to arrange code in ABI neutral
# manner. Therefore let's stick to NUBI register layout:
#
($zero,$at,$t0,$t1,$t2)=map("\$$_",(0..2,24,25));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("\$$_",(12..23));
($gp,$tp,$sp,$fp,$ra)=map("\$$_",(3,28..31));
#
# The return value is placed in $a0. Following coding rules facilitate
# interoperability:
#
# - never ever touch $tp, "thread pointer", former $gp [o32 can be
#   excluded from the rule, because it's specified volatile];
# - copy return value to $t0, former $v0 [or to $a0 if you're adapting
#   old code];
# - on O32 populate $a4-$a7 with 'lw $aN,4*N($sp)' if necessary;
#
# For reference here is register layout for N32/64 MIPS ABIs:
#
# ($zero,$at,$v0,$v1)=map("\$$_",(0..3));
# ($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$$_",(4..11));
# ($t0,$t1,$t2,$t3,$t8,$t9)=map("\$$_",(12..15,24,25));
# ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7)=map("\$$_",(16..23));
# ($gp,$sp,$fp,$ra)=map("\$$_",(28..31));
#
######################################################################

$flavour = shift || "64"; # supported flavours are o32,n32,64,nubi32,nubi64

($v0, $v1) = ($flavour =~ /nubi/i) ? ($a0, $a1) : ($t0, $gp);

for (@ARGV) {   $output=$_ if (/\w[\w\-]*\.\w+$/);   }
open STDOUT,">$output";

$code=<<___;
.text
.set	noat
.set	reorder
___
$code.=<<___	if ($flavour =~ /64|n32/);
.globl	ct_umull
.align	4
.ent	ct_umull
ct_umull:
	.frame	$sp,0,$ra
	li	$t0, -1
	li	$t1, 3
	dsrl	$t0, $t0, 32		# 0xffffffff
	dsll	$t1, $t1, 32		# 0x300000000
	and	$a0, $a0, $t0		# arguments are passed sign-extended,
	and	$a1, $a1, $t0		# so clear the upper 32 bits.

	or	$a2, $a0, $t1
	or	$a3, $a1, $t1
	daddu	$a4, $a0, $a1

#if defined(_MIPS_ARCH_MIPS64R6)
	dmulu	$a0, $a2, $a3
#else
	dmultu	$a2, $a3
	mflo	$a0
#endif

	dsll	$a3, $a4, 33
	dsll	$a4, $a4, 32
	dsubu	$a0, $a0, $a3
	dsubu	$v0, $a0, $a4
	jr	$ra
.end	ct_umull
___
$code.=<<___	if ($flavour !~ /64|n32/);
#if defined(__MIPSEB__) && !defined(MIPSEB)
# define MIPSEB
#endif
#ifdef MIPSEB
# define LO $v1
# define HI $v0
#else
# define LO $v0
# define HI $v1
#endif

.globl	ct_umull
.align	4
.ent	ct_umull
ct_umull:
	.frame	$sp,0,$ra
	lui	$t0, 0x8000
	sra	$a2, $a0, 31
	sra	$a3, $a1, 31
	nor	$a2, $zero, $a2
	nor	$a3, $zero, $a3
	and	$a4, $a2, $a1
	and	$a5, $a3, $a0
	or	$a0, $a0, $t0	# |a||0x80000000
	or	$a1, $a1, $t0	# |b||0x80000000

#if defined(_MIPS_ARCH_MIPS32R6)
	mulu	$a6, $a0, $a1
	muhu	$a7, $a0, $a1
#else
	multu	$a0, $a1
	mflo	$a6
	mfhi	$a7
#endif
	lui	$t0, 0x4000
	and	$a2, $a2, $a3
	addu	$a5, $a5, $a4
	and	$a2, $a2, $t0
	sll	$a4, $a5, 31
	srl	$a5, $a5, 1

	sltu	$a3, $a6, $a4
	addu	$a5, $a5, $a2
	subu	LO, $a6, $a4
	subu	$a7, $a7, $a5
	subu	HI, $a7, $a3
	jr	$ra
.end	ct_umull
___

print $code;
close STDOUT;
