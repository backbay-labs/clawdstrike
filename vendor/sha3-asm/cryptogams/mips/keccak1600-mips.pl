#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Keccak-1600 for MIPS.
#
# March 2019
#
# 64-bit code path is lane-complementing KECCAK_1X_ALT, with twist.
# On boundary to __KeccakF1600 whole A[][] is held in registers,
# but A[0][] is offloaded to stack during calculations to make room
# for D[].
#
# R1x000	19.6/+200%	(big-endian)
# Octeon II	15.8/+75%	(little-endian)
#
# 32-bit code path is lane-complementing KECCAK_2X variant with bit
# interleaving. C[] and D[] are held in registers.
#
# R1x000	48/?		(big-endian)
# Octeon II	45/+45%		(little-endian)
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

$flavour = shift || "o32"; # supported flavours are o32,n32,64,nubi32,nubi64

$pf = ($flavour =~ /nubi/i) ? $t0 : $t2;
$SAVED_REGS_MASK = ($flavour =~ /nubi/i) ? "0xc0fff008" : "0xc0ff0000";

for (@ARGV) {   $output=$_ if (/\w[\w\-]*\.\w+$/);   }
open STDOUT,">$output";

my @rhotates = ([  0,  1, 62, 28, 27 ],
		[ 36, 44,  6, 55, 20 ],
		[  3, 10, 43, 25, 39 ],
		[ 41, 45, 15, 21,  8 ],
		[ 18,  2, 61, 56, 14 ]);

######################################################################
# 64-bit code path...
#
if ($flavour =~ /64|n32/i) {{{
# registers
my @A = map([ "\$$_", "\$".($_+1), "\$".($_+2), "\$".($_+3), "\$".($_+4) ],
            (1, 6, 11, 16, 21));
{
my @T = ($ra,$fp, $A[4][0],$A[4][1]);
my @D = ($A[0][4],$A[0][0],$A[0][1],$A[0][2],$A[0][3]);

# offsets into stack frame
my @E = map(8*$_, (0..4));
my @F = map(8*$_, (5..9));
my ($iotas,$_ra) = map(8*$_,(10..11));

$code.=<<___;
#if (defined(_MIPS_ARCH_MIPS64R3) || defined(_MIPS_ARCH_MIPS64R5) || \\
     defined(_MIPS_ARCH_MIPS64R6)) \\
     && !defined(_MIPS_ARCH_MIPS64R2)
# define _MIPS_ARCH_MIPS64R2
#endif

#if defined(__MIPSEB__) && !defined(MIPSEB)
# define MIPSEB
#endif

.text
.option	pic2
.set	noat
.set	reorder

.align	5
.ent	__KeccakF1600
__KeccakF1600:
	.frame	$sp, 8*12, $ra
	.mask	0x80000000, -8
	dsubu	$sp, $sp, 8*12
	sd	$ra, $_ra($sp)

	sd	$A[4][0], $F[0]($sp)
	sd	$A[4][1], $F[1]($sp)

.Loop:
	 sd	$fp, $iotas($sp)		# offload iotas
	 sd	$A[0][2], $E[2]($sp)		# offload A[0][*]
	xor	$D[3], $A[0][2], $A[1][2]
	 sd	$A[0][3], $E[3]($sp)
	xor	$D[4], $A[0][3], $A[1][3]
	 sd	$A[0][0], $E[0]($sp)
	xor	$T[0], $A[0][0], $A[1][0]
	 sd	$A[0][1], $E[1]($sp)
	xor	$T[1], $A[0][1], $A[1][1]
	 sd	$A[0][4], $E[4]($sp)
	xor	$D[0], $A[0][4], $A[1][4]

	 ld	$A[4][0], $F[0]($sp)		# reload A[4][1..2]
	xor	$T[0], $T[0], $A[2][0]
	 ld	$A[4][1], $F[1]($sp)
	xor	$T[1], $T[1], $A[2][1]
	xor	$D[3], $D[3], $A[2][2]
	xor	$D[4], $D[4], $A[2][3]
	xor	$D[0], $D[0], $A[2][4]

	xor	$T[0], $T[0], $A[3][0]
	xor	$T[1], $T[1], $A[3][1]
	xor	$D[3], $D[3], $A[3][2]
	xor	$D[4], $D[4], $A[3][3]
	xor	$D[0], $D[0], $A[3][4]

	xor	$T[0], $T[0], $A[4][0]
	xor	$T[1], $T[1], $A[4][1]
	xor	$D[3], $D[3], $A[4][2]
	xor	$D[4], $D[4], $A[4][3]
	xor	$D[0], $D[0], $A[4][4]

#ifdef	_MIPS_ARCH_MIPS64R2
	drotr	$D[1], $D[3], 63
	drotr	$D[2], $D[0], 63
	xor	$D[1], $D[1], $T[0]		# D[1] = T[0] ^ ROL64(D[3], 1);
	xor	$D[3], $D[3], $D[2]		# D[3] ^= ROL64(D[0], 1);
	drotr	$D[2], $T[1], 63
	xor	$D[0], $D[0], $D[2]		# D[0] ^= ROL64(T[1], 1);
	drotr	$T[0], $T[0], 63
	drotr	$D[2], $D[4], 63
	xor	$D[4], $D[4], $T[0]		# D[4] ^= ROL64(T[0], 1);
	xor	$D[2], $D[2], $T[1]		# D[2] = T[1] ^ ROL64(D[4], 1);

	xor	$T[0], $A[1][1], $D[1]
	xor	$T[1], $A[2][2], $D[2]
	drotr	$T[0], $T[0], 64-$rhotates[1][1]
	drotr	$T[1], $T[1], 64-$rhotates[2][2]
	 sd	$T[0], $F[1]($sp)		# offload new A[0][*]
	xor	$T[0], $A[3][3], $D[3]
	 sd	$T[1], $F[2]($sp)
	xor	$T[1], $A[4][4], $D[4]
	drotr	$T[0], $T[0], 64-$rhotates[3][3]
	drotr	$T[1], $T[1], 64-$rhotates[4][4]

	xor	$A[1][1], $A[1][4], $D[4]
	xor	$A[2][2], $A[2][3], $D[3]
	xor	$A[3][3], $A[3][2], $D[2]
	xor	$A[4][4], $A[4][1], $D[1]
	drotr	$A[1][1], $A[1][1], 64-$rhotates[1][4]
	 sd	$T[0], $F[3]($sp)
	drotr	$A[2][2], $A[2][2], 64-$rhotates[2][3]
	 sd	$T[1], $F[4]($sp)
	drotr	$A[3][3], $A[3][3], 64-$rhotates[3][2]
	drotr	$A[4][4], $A[4][4], 64-$rhotates[4][1]

	xor	$A[1][4], $A[4][2], $D[2]
	xor	$A[2][3], $A[3][4], $D[4]
	xor	$A[3][2], $A[2][1], $D[1]
	xor	$A[4][1], $A[1][3], $D[3]
	drotr	$A[1][4], $A[1][4], 64-$rhotates[4][2]
	drotr	$A[2][3], $A[2][3], 64-$rhotates[3][4]
	drotr	$A[3][2], $A[3][2], 64-$rhotates[2][1]
	drotr	$A[4][1], $A[4][1], 64-$rhotates[1][3]

	xor	$A[4][2], $A[2][4], $D[4]
	xor	$A[3][4], $A[4][3], $D[3]
	xor	$A[2][1], $A[1][2], $D[2]
	xor	$A[1][3], $A[3][1], $D[1]
	drotr	$A[4][2], $A[4][2], 64-$rhotates[2][4]
	drotr	$A[3][4], $A[3][4], 64-$rhotates[4][3]
	drotr	$A[2][1], $A[2][1], 64-$rhotates[1][2]
	drotr	$A[1][3], $A[1][3], 64-$rhotates[3][1]

	xor	$A[2][4], $A[4][0], $D[0]
	 ld	$A[4][0], $E[2]($sp)		# load original A[0][*]
	xor	$A[4][3], $A[3][0], $D[0]
	 ld	$A[3][0], $E[4]($sp)
	xor	$A[1][2], $A[2][0], $D[0]
	 ld	$A[2][0], $E[1]($sp)
	xor	$A[3][1], $A[1][0], $D[0]
	 ld	$A[1][0], $E[3]($sp)
	drotr	$A[2][4], $A[2][4], 64-$rhotates[4][0]
	drotr	$A[4][3], $A[4][3], 64-$rhotates[3][0]
	drotr	$A[1][2], $A[1][2], 64-$rhotates[2][0]
	drotr	$A[3][1], $A[3][1], 64-$rhotates[1][0]

	xor	$A[4][0], $A[4][0], $D[2]
	xor	$A[3][0], $A[3][0], $D[4]
	xor	$A[2][0], $A[2][0], $D[1]
	xor	$A[1][0], $A[1][0], $D[3]
	drotr	$A[4][0], $A[4][0], 64-$rhotates[0][2]
	drotr	$A[3][0], $A[3][0], 64-$rhotates[0][4]
	drotr	$A[2][0], $A[2][0], 64-$rhotates[0][1]
	drotr	$A[1][0], $A[1][0], 64-$rhotates[0][3]
#else
	daddu	$D[1], $D[3], $D[3]		# dsll $D[3], 1
	xor	$D[1], $D[1], $T[0]
	dsrl	$D[2], $D[3], 63
	xor	$D[1], $D[1], $D[2]		# D[1] = T[0] ^ ROL64(D[3], 1);
	daddu	$D[2], $D[0], $D[0]		# dsll $D[0], 1
	xor	$D[3], $D[3], $D[2]
	dsrl	$D[2], $D[0], 63
	xor	$D[3], $D[3], $D[2]		# D[3] ^= ROL64(D[0], 1);
	daddu	$D[2], $T[1], $T[1]		# dsll $T[1], 1
	xor	$D[0], $D[0], $D[2]
	dsrl	$D[2], $T[1], 63
	xor	$D[0], $D[0], $D[2]		# D[0] ^= ROL64(T[1], 1);
	daddu	$D[2], $D[4], $D[4]		# dsll $D[4], 1
	xor	$D[2], $D[2], $T[1]
	dsrl	$T[1], $D[4], 63
	xor	$D[2], $D[2], $T[1]		# D[2] = T[1] ^ ROL64(D[4], 1);
	daddu	$T[1], $T[0], $T[0]		# dsll $T[0], 1
	xor	$D[4], $D[4], $T[1]
	dsrl	$T[1], $T[0], 63
	xor	$D[4], $D[4], $T[1]		# D[4] ^= ROL64(T[0], 1);


	xor	$T[0], $A[1][1], $D[1]
	dsll	$T[1], $T[0], $rhotates[1][1]
	dsrl	$T[0], $T[0], 64-$rhotates[1][1]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[2][2], $D[2]
	 sd	$T[1], $F[1]($sp)		# offload new A[0][*]
	dsll	$T[1], $T[0], $rhotates[2][2]
	dsrl	$T[0], $T[0], 64-$rhotates[2][2]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[3][3], $D[3]
	 sd	$T[1], $F[2]($sp)
	dsll	$T[1], $T[0], $rhotates[3][3]
	dsrl	$T[0], $T[0], 64-$rhotates[3][3]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[4][4], $D[4]
	 sd	$T[1], $F[3]($sp)
	dsll	$T[1], $T[0], $rhotates[4][4]
	dsrl	$T[0], $T[0], 64-$rhotates[4][4]
	or	$T[1], $T[1], $T[0]


	xor	$A[1][1], $A[1][4], $D[4]
	 xor	$A[2][2], $A[2][3], $D[3]
	  sd	$T[1], $F[4]($sp)
	dsrl	$T[0], $A[1][1], 64-$rhotates[1][4]
	 dsrl	$T[1], $A[2][2], 64-$rhotates[2][3]
	dsll	$A[1][1], $A[1][1], $rhotates[1][4]
	 dsll	$A[2][2], $A[2][2], $rhotates[2][3]

	xor	$A[3][3], $A[3][2], $D[2]
	 xor	$A[4][4], $A[4][1], $D[1]
	  or	$A[1][1], $A[1][1], $T[0]
	dsrl	$T[0], $A[3][3], 64-$rhotates[3][2]
	   or	$A[2][2], $A[2][2], $T[1]
	 dsrl	$T[1], $A[4][4], 64-$rhotates[4][1]
	dsll	$A[3][3], $A[3][3], $rhotates[3][2]
	 dsll	$A[4][4], $A[4][4], $rhotates[4][1]


	xor	$A[1][4], $A[4][2], $D[2]
	 xor	$A[2][3], $A[3][4], $D[4]
	  or	$A[3][3], $A[3][3], $T[0]
	dsrl	$T[0], $A[1][4], 64-$rhotates[4][2]
	   or	$A[4][4], $A[4][4], $T[1]
	 dsrl	$T[1], $A[2][3], 64-$rhotates[3][4]
	dsll	$A[1][4], $A[1][4], $rhotates[4][2]
	 dsll	$A[2][3], $A[2][3], $rhotates[3][4]

	xor	$A[3][2], $A[2][1], $D[1]
	 xor	$A[4][1], $A[1][3], $D[3]
	  or	$A[1][4], $A[1][4], $T[0]
	dsrl	$T[0], $A[3][2], 64-$rhotates[2][1]
	   or	$A[2][3], $A[2][3], $T[1]
	 dsrl	$T[1], $A[4][1], 64-$rhotates[1][3]
	dsll	$A[3][2], $A[3][2], $rhotates[2][1]
	 dsll	$A[4][1], $A[4][1], $rhotates[1][3]


	xor	$A[4][2], $A[2][4], $D[4]
	 xor	$A[3][4], $A[4][3], $D[3]
	  or	$A[3][2], $A[3][2], $T[0]
	dsrl	$T[0], $A[4][2], 64-$rhotates[2][4]
	   or	$A[4][1], $A[4][1], $T[1]
	 dsrl	$T[1], $A[3][4], 64-$rhotates[4][3]
	dsll	$A[4][2], $A[4][2], $rhotates[2][4]
	 dsll	$A[3][4], $A[3][4], $rhotates[4][3]

	xor	$A[2][1], $A[1][2], $D[2]
	 xor	$A[1][3], $A[3][1], $D[1]
	  or	$A[4][2], $A[4][2], $T[0]
	dsrl	$T[0], $A[2][1], 64-$rhotates[1][2]
	   or	$A[3][4], $A[3][4], $T[1]
	 dsrl	$T[1], $A[1][3], 64-$rhotates[3][1]
	dsll	$A[2][1], $A[2][1], $rhotates[1][2]
	 dsll	$A[1][3], $A[1][3], $rhotates[3][1]


	xor	$A[2][4], $A[4][0], $D[0]
	  ld	$A[4][0], $E[2]($sp)		# load original A[0][*]
	 xor	$A[4][3], $A[3][0], $D[0]
	  ld	$A[3][0], $E[4]($sp)
	  or	$A[2][1], $A[2][1], $T[0]
	dsrl	$T[0], $A[2][4], 64-$rhotates[4][0]
	   or	$A[1][3], $A[1][3], $T[1]
	 dsrl	$T[1], $A[4][3], 64-$rhotates[3][0]
	dsll	$A[2][4], $A[2][4], $rhotates[4][0]
	 dsll	$A[4][3], $A[4][3], $rhotates[3][0]

	xor	$A[1][2], $A[2][0], $D[0]
	  ld	$A[2][0], $E[1]($sp)
	 xor	$A[3][1], $A[1][0], $D[0]
	  ld	$A[1][0], $E[3]($sp)
	  or	$A[2][4], $A[2][4], $T[0]
	dsrl	$T[0], $A[1][2], 64-$rhotates[2][0]
	   or	$A[4][3], $A[4][3], $T[1]
	 dsrl	$T[1], $A[3][1], 64-$rhotates[1][0]
	dsll	$A[1][2], $A[1][2], $rhotates[2][0]
	 dsll	$A[3][1], $A[3][1], $rhotates[1][0]


	xor	$A[4][0], $A[4][0], $D[2]
	 xor	$A[3][0], $A[3][0], $D[4]
	  or	$A[1][2], $A[1][2], $T[0]
	dsrl	$T[0], $A[4][0], 64-$rhotates[0][2]
	   or	$A[3][1], $A[3][1], $T[1]
	 dsrl	$T[1], $A[3][0], 64-$rhotates[0][4]
	dsll	$A[4][0], $A[4][0], $rhotates[0][2]
	 dsll	$A[3][0], $A[3][0], $rhotates[0][4]

	xor	$A[2][0], $A[2][0], $D[1]
	 xor	$A[1][0], $A[1][0], $D[3]
	  or	$A[4][0], $A[4][0], $T[0]
	dsrl	$T[0], $A[2][0], 64-$rhotates[0][1]
	   or	$A[3][0], $A[3][0], $T[1]
	 dsrl	$T[1], $A[1][0], 64-$rhotates[0][3]
	dsll	$A[2][0], $A[2][0], $rhotates[0][1]
	 dsll	$A[1][0], $A[1][0], $rhotates[0][3]
	or	$A[2][0], $A[2][0], $T[0]
	 or	$A[1][0], $A[1][0], $T[1]
#endif

	not	$D[2], $A[1][4]
	or	$T[0], $A[1][1], $A[1][2]
	and	$D[1], $A[1][2], $A[1][3]
	or	$D[2], $D[2], $A[1][3]
	or	$D[3], $A[1][4], $A[1][0]
	and	$D[4], $A[1][0], $A[1][1]
	xor	$A[1][0], $A[1][0], $T[0]
	xor	$A[1][1], $A[1][1], $D[1]
	xor	$A[1][2], $A[1][2], $D[2]
	xor	$A[1][3], $A[1][3], $D[3]
	xor	$A[1][4], $A[1][4], $D[4]

	or	$T[0], $A[2][1], $A[2][2]
	and	$D[1], $A[2][2], $A[2][3]
	not	$A[2][3], $A[2][3]
	or	$D[3], $A[2][4], $A[2][0]
	and	$D[4], $A[2][0], $A[2][1]
	and	$D[2], $A[2][3], $A[2][4]
	xor	$A[2][0], $A[2][0], $T[0]
	xor	$A[2][1], $A[2][1], $D[1]
	xor	$A[2][2], $A[2][2], $D[2]
	xor	$A[2][3], $A[2][3], $D[3]
	xor	$A[2][4], $A[2][4], $D[4]

	and	$T[0], $A[3][1], $A[3][2]
	or	$D[1], $A[3][2], $A[3][3]
	not	$A[3][3], $A[3][3]
	and	$D[3], $A[3][4], $A[3][0]
	or	$D[4], $A[3][0], $A[3][1]
	or	$D[2], $A[3][3], $A[3][4]
	 not	$T[1], $A[4][1]
	xor	$A[3][0], $A[3][0], $T[0]
	xor	$A[3][1], $A[3][1], $D[1]
	xor	$A[3][2], $A[3][2], $D[2]
	xor	$A[3][3], $A[3][3], $D[3]
	xor	$A[3][4], $A[3][4], $D[4]

	and	$T[0], $T[1], $A[4][2]
	or	$D[1], $A[4][2], $A[4][3]
	and	$D[2], $A[4][3], $A[4][4]
	or	$D[3], $A[4][4], $A[4][0]
	and	$D[4], $A[4][0], $A[4][1]
	xor	$A[4][0], $A[4][0], $T[0]
	xor	$A[4][1], $T[1], $D[1]
	 ld	$A[0][0], $E[0]($sp)		# reload A[0][*]
	xor	$A[4][2], $A[4][2], $D[2]
	 ld	$A[0][1], $F[1]($sp)
	xor	$A[4][3], $A[4][3], $D[3]
	 ld	$A[0][2], $F[2]($sp)
	xor	$A[4][4], $A[4][4], $D[4]
	 ld	$A[0][3], $F[3]($sp)

	xor	$A[0][0], $A[0][0], $D[0]
	 ld	$A[0][4], $F[4]($sp)

	not	$T[1], $A[0][2]
	or	$T[0], $A[0][1], $A[0][2]
	or	$T[1], $T[1], $A[0][3]
	 sd	$A[4][0], $F[0]($sp)		# make room for T[2]
	and	$T[2], $A[0][3], $A[0][4]
	 sd	$A[4][1], $F[1]($sp)		# make room for T[3]
	or	$T[3], $A[0][4], $A[0][0]
	xor	$A[0][2], $A[0][2], $T[2]
	and	$T[2], $A[0][0], $A[0][1]
	xor	$A[0][3], $A[0][3], $T[3]
	 ld	$T[3], $iotas($sp)
	xor	$A[0][4], $A[0][4], $T[2]
	xor	$A[0][0], $A[0][0], $T[0]
	xor	$A[0][1], $A[0][1], $T[1]

	ld	$T[2], 0($T[3])
	daddu	$fp, $T[3], 8			# iotas++, fp is T[1]

	andi	$T[0], $fp, 0xff
	xor	$A[0][0], $A[0][0], $T[2]	# A[0][0] ^= iotas[i]
	bnez	$T[0], .Loop

	ld	$ra, $_ra($sp)

	ld	$A[4][0], $F[0]($sp)
	ld	$A[4][1], $F[1]($sp)

	daddu	$sp, $sp, 8*12
	jr	$ra
.end	__KeccakF1600

.align	5
.ent	KeccakF1600
KeccakF1600:
	.frame	$sp, 8*16, $ra
	.mask	$SAVED_REGS_MASK, 8
	dsubu	$sp, $sp, 8*16

	sd	$ra,  8*15($sp)
	sd	$fp,  8*14($sp)
	sd	$s11, 8*13($sp)
	sd	$s10, 8*12($sp)
	sd	$s9,  8*11($sp)
	sd	$s8,  8*10($sp)
	sd	$s7,  8*9($sp)
	sd	$s6,  8*8($sp)
	sd	$s5,  8*7($sp)
	sd	$s4,  8*6($sp)
___
$code.=<<___	if ($flavour =~ /nubi/);
	sd	$s3,  8*5($sp)
	sd	$s2,  8*4($sp)
	sd	$s1,  8*3($sp)
	sd	$s0,  8*2($sp)
	sd	$gp,  8*1($sp)
___
$code.=<<___;
	#dla	$fp, iotas			# caller's responsibility
	sd	$a0, 0($sp)
	move	$ra, $a0

	ld	$A[0][0], 0x00($a0)
	ld	$A[0][1], 0x08($a0)
	ld	$A[0][2], 0x10($a0)
	ld	$A[0][3], 0x18($a0)
	ld	$A[0][4], 0x20($ra)
	ld	$A[1][0], 0x28($ra)
	ld	$A[1][1], 0x30($ra)
	ld	$A[1][2], 0x38($ra)
	ld	$A[1][3], 0x40($ra)
	ld	$A[1][4], 0x48($ra)
	ld	$A[2][0], 0x50($ra)
	ld	$A[2][1], 0x58($ra)
	ld	$A[2][2], 0x60($ra)
	ld	$A[2][3], 0x68($ra)
	ld	$A[2][4], 0x70($ra)
	ld	$A[3][0], 0x78($ra)
	ld	$A[3][1], 0x80($ra)
	ld	$A[3][2], 0x88($ra)
	ld	$A[3][3], 0x90($ra)
	ld	$A[3][4], 0x98($ra)
	ld	$A[4][0], 0xa0($ra)
	ld	$A[4][1], 0xa8($ra)
	ld	$A[4][2], 0xb0($ra)
	ld	$A[4][3], 0xb8($ra)
	ld	$A[4][4], 0xc0($ra)

	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]

	bal	__KeccakF1600

	ld	$fp, 0($sp)

	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]

	sd	$A[0][0], 0x00($fp)
	sd	$A[0][1], 0x08($fp)
	sd	$A[0][2], 0x10($fp)
	sd	$A[0][3], 0x18($fp)
	sd	$A[0][4], 0x20($fp)
	sd	$A[1][0], 0x28($fp)
	sd	$A[1][1], 0x30($fp)
	sd	$A[1][2], 0x38($fp)
	sd	$A[1][3], 0x40($fp)
	sd	$A[1][4], 0x48($fp)
	sd	$A[2][0], 0x50($fp)
	sd	$A[2][1], 0x58($fp)
	sd	$A[2][2], 0x60($fp)
	sd	$A[2][3], 0x68($fp)
	sd	$A[2][4], 0x70($fp)
	sd	$A[3][0], 0x78($fp)
	sd	$A[3][1], 0x80($fp)
	sd	$A[3][2], 0x88($fp)
	sd	$A[3][3], 0x90($fp)
	sd	$A[3][4], 0x98($fp)
	sd	$A[4][0], 0xa0($fp)
	sd	$A[4][1], 0xa8($fp)
	sd	$A[4][2], 0xb0($fp)
	sd	$A[4][3], 0xb8($fp)
	sd	$A[4][4], 0xc0($fp)

	ld	$ra,  8*15($sp)
	ld	$fp,  8*14($sp)
	ld	$s11, 8*13($sp)
	ld	$s10, 8*12($sp)
	ld	$s9,  8*11($sp)
	ld	$s8,  8*10($sp)
	ld	$s7,  8*9($sp)
	ld	$s6,  8*8($sp)
	ld	$s5,  8*7($sp)
	ld	$s4,  8*6($sp)
___
$code.=<<___	if ($flavour =~ /nubi/);
	ld	$s3,  8*5($sp)
	ld	$s2,  8*4($sp)
	ld	$s1,  8*3($sp)
	ld	$s0,  8*2($sp)
	ld	$gp,  8*2($sp)
___
$code.=<<___;
	daddu	$sp, $sp, 8*16
	jr	$ra
.end	KeccakF1600
___
}
{
my ($inp,$len,$bsz) = ($A[4][2],$A[4][3],$A[4][4]);
my @T = ($A[4][1],$len,$ra);

$code.=<<___;
#if defined(MIPSEB) || defined(_MIPS_ARCH_MIPS64R6)
.align	5
.ent	__load_n_xor
__load_n_xor:
	lbu	$T[0], 0($inp)
	lbu	$T[1], 1($inp)
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 2($inp)
	dsll	$T[1], $T[1], 8
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 3($inp)
	dsll	$T[0], $T[0], 16
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 4($inp)
	dsll	$T[1], $T[1], 24
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 5($inp)
	dsll	$T[0], $T[0], 32
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 6($inp)
	dsll	$T[1], $T[1], 40
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 7($inp)
	dsll	$T[0], $T[0], 48
	xor	$A[4][0], $A[4][0], $T[0]
	dsll	$T[1], $T[1], 56
	xor	$A[4][0], $A[4][0], $T[1]
	daddu	$inp, $inp, 8
	jr	$ra
.end	__load_n_xor
#endif

.globl	SHA3_absorb
.align	5
.ent	SHA3_absorb
SHA3_absorb:
	.frame	$sp, 8*20, $ra
	.mask	$SAVED_REGS_MASK, -8
	.set	noreorder
	sltu	$at, $a2, $a3			# len < bsz?
	bnez	$at,.Labsorb_abort
	nop

	dsubu	$sp, $sp, 8*20

	sd	$ra,  8*19($sp)
	sd	$fp,  8*18($sp)
	sd	$s11, 8*17($sp)
	sd	$s10, 8*16($sp)
	sd	$s9,  8*15($sp)
	sd	$s8,  8*14($sp)
	sd	$s7,  8*13($sp)
	sd	$s6,  8*12($sp)
	sd	$s5,  8*11($sp)
	sd	$s4,  8*10($sp)
___
$code.=<<___	if ($flavour =~ /nubi/);
	sd	$s3,  8*9($sp)
	sd	$s2,  8*8($sp)
	sd	$s1,  8*7($sp)
	sd	$s0,  8*6($sp)
	sd	$gp,  8*5($sp)
___
$code.=<<___;
	.cplocal $ra
	.cpsetup $pf, $zero, SHA3_absorb
	.set	reorder

	move	$fp,  $a0
	dla	$ra,  iotas
	move	$inp, $a1
	sd	$a0,  8*0($sp)			# put aside A[][]
	move	$len, $a2
	sd	$a3,  8*3($sp)			# put aside bsz
	move	$bsz, $a3

	ld	$A[0][0], 0x00($a0)
	ld	$A[0][1], 0x08($a0)
	ld	$A[0][2], 0x10($a0)
	ld	$A[0][3], 0x18($a0)
	ld	$A[0][4], 0x20($fp)
	ld	$A[1][0], 0x28($fp)
	ld	$A[1][1], 0x30($fp)
	ld	$A[1][2], 0x38($fp)
	ld	$A[1][3], 0x40($fp)
	ld	$A[1][4], 0x48($fp)
	ld	$A[2][0], 0x50($fp)
	ld	$A[2][1], 0x58($fp)
	ld	$A[2][2], 0x60($fp)
	ld	$A[2][3], 0x68($fp)
	ld	$A[2][4], 0x70($fp)
	ld	$A[3][0], 0x78($fp)
	ld	$A[3][1], 0x80($fp)
	ld	$A[3][2], 0x88($fp)
	ld	$A[3][3], 0x90($fp)
	ld	$A[3][4], 0x98($fp)
	ld	$A[4][0], 0xa0($fp)

	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]

	sd	$ra, 8*4($sp)			# put aside iotas

.Loop_absorb:
	dsubu	$len, $len, $bsz
	daddu	$ra,  $inp, $bsz		# pointer to next block
	sd	$len, 8*2($sp)
	sd	$ra,  8*1($sp)

#if !defined(MIPSEB) && !defined(_MIPS_ARCH_MIPS64R6)
	ldl	$T[0], 8*0+7($inp)		# load [misaligned] input
	ldl	$T[1], 8*1+7($inp)
	ldl	$T[2], 8*2+7($inp)
	ldr	$T[0], 8*0+0($inp)
	ldr	$T[1], 8*1+0($inp)
	ldr	$T[2], 8*2+0($inp)
	xor	$A[0][0], $A[0][0], $T[0]
	xor	$A[0][1], $A[0][1], $T[1]
	xor	$A[0][2], $A[0][2], $T[2]
	ldl	$T[0], 8*3+7($inp)
	ldl	$T[1], 8*4+7($inp)
	ldl	$T[2], 8*5+7($inp)
	ldr	$T[0], 8*3+0($inp)
	ldr	$T[1], 8*4+0($inp)
	ldr	$T[2], 8*5+0($inp)
	xor	$A[0][3], $A[0][3], $T[0]
	xor	$A[0][4], $A[0][4], $T[1]
	xor	$A[1][0], $A[1][0], $T[2]
	ldl	$T[0], 8*6+7($inp)
	ldl	$T[1], 8*7+7($inp)
	ldl	$T[2], 8*8+7($inp)
	ldr	$T[0], 8*6+0($inp)
	ldr	$T[1], 8*7+0($inp)
	ldr	$T[2], 8*8+0($inp)
	xor	$A[1][1], $A[1][1], $T[0]
	xor	$A[1][2], $A[1][2], $T[1]
	li	$T[0], 72
	xor	$A[1][3], $A[1][3], $T[2]
	beq	$bsz, $T[0], .Lprocess_block

	ldl	$T[0], 8*9+7($inp)
	ldl	$T[1], 8*10+7($inp)
	ldr	$T[0], 8*9+0($inp)
	ldr	$T[1], 8*10+0($inp)
	xor	$A[1][4],$A[1][4],$T[0]
	xor	$A[2][0],$A[2][0],$T[1]
	ldl	$T[0], 8*11+7($inp)
	ldl	$T[1], 8*12+7($inp)
	ldr	$T[0], 8*11+0($inp)
	ldr	$T[1], 8*12+0($inp)
	xor	$A[2][1],$A[2][1],$T[0]
	li	$T[0], 104
	xor	$A[2][2],$A[2][2],$T[1]
	beq	$bsz, $T[0], .Lprocess_block

	ldl	$T[0], 8*13+7($inp)
	ldl	$T[1], 8*14+7($inp)
	ldr	$T[0], 8*13+0($inp)
	ldr	$T[1], 8*14+0($inp)
	xor	$A[2][3],$A[2][3],$T[0]
	xor	$A[2][4],$A[2][4],$T[1]
	ldl	$T[0], 8*15+7($inp)
	ldl	$T[1], 8*16+7($inp)
	ldr	$T[0], 8*15+0($inp)
	ldr	$T[1], 8*16+0($inp)
	xor	$A[3][0],$A[3][0],$T[0]
	li	$T[0], 136
	xor	$A[3][1],$A[3][1],$T[1]
	beq	$bsz, $T[0], .Lprocess_block

	ldl	$T[2], 8*17+7($inp)
	ldr	$T[2], 8*17+0($inp)
	li	$T[0], 144
	xor	$A[3][2],$A[3][2],$T[2]
	beq	$bsz, $T[0], .Lprocess_block

	ldl	$T[0], 8*18+7($inp)
	ldl	$T[1], 8*19+7($inp)
	ldl	$T[2], 8*20+7($inp)
	ldr	$T[0], 8*18+0($inp)
	ldr	$T[1], 8*19+0($inp)
	ldr	$T[2], 8*20+0($inp)
	xor	$A[3][3],$A[3][3],$T[0]
	xor	$A[3][4],$A[3][4],$T[1]
	xor	$A[4][0],$A[4][0],$T[2]
#else
	sd	$A[4][0], 0xa0($fp)		# borrow even A[4][0]

	move	$A[4][0], $A[0][0]
	bal	__load_n_xor
	move	$A[0][0],$A[4][0]
	move	$A[4][0], $A[0][1]
	bal	__load_n_xor
	move	$A[0][1],$A[4][0]
	move	$A[4][0], $A[0][2]
	bal	__load_n_xor
	move	$A[0][2],$A[4][0]
	move	$A[4][0], $A[0][3]
	bal	__load_n_xor
	move	$A[0][3],$A[4][0]
	move	$A[4][0], $A[0][4]
	bal	__load_n_xor
	move	$A[0][4],$A[4][0]
	move	$A[4][0], $A[1][0]
	bal	__load_n_xor
	move	$A[1][0],$A[4][0]
	move	$A[4][0], $A[1][1]
	bal	__load_n_xor
	move	$A[1][1],$A[4][0]
	move	$A[4][0], $A[1][2]
	bal	__load_n_xor
	move	$A[1][2],$A[4][0]
	move	$A[4][0], $A[1][3]
	bal	__load_n_xor
	li	$T[0], 72
	move	$A[1][3],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	move	$A[4][0], $A[1][4]
	bal	__load_n_xor
	move	$A[1][4],$A[4][0]
	move	$A[4][0], $A[2][0]
	bal	__load_n_xor
	move	$A[2][0],$A[4][0]
	move	$A[4][0], $A[2][1]
	bal	__load_n_xor
	move	$A[2][1],$A[4][0]
	move	$A[4][0], $A[2][2]
	bal	__load_n_xor
	li	$T[0], 104
	move	$A[2][2],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	move	$A[4][0], $A[2][3]
	bal	__load_n_xor
	move	$A[2][3],$A[4][0]
	move	$A[4][0], $A[2][4]
	bal	__load_n_xor
	move	$A[2][4],$A[4][0]
	move	$A[4][0], $A[3][0]
	bal	__load_n_xor
	move	$A[3][0],$A[4][0]
	move	$A[4][0], $A[3][1]
	bal	__load_n_xor
	li	$T[0], 136
	move	$A[3][1],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	move	$A[4][0], $A[3][2]
	bal	__load_n_xor
	li	$T[0], 144
	move	$A[3][2],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	move	$A[4][0], $A[3][3]
	bal	__load_n_xor
	move	$A[3][3],$A[4][0]
	move	$A[4][0], $A[3][4]
	bal	__load_n_xor
	move	$A[3][4],$A[4][0]
	ld	$A[4][0], 0xa0($fp)
	bal	__load_n_xor
	b	.Lprocess_block

.Lprocess_block2:
	ld	$A[4][0], 0xa0($fp)
#endif

.Lprocess_block:
	ld	$A[4][1], 0xa8($fp)
	ld	$A[4][2], 0xb0($fp)
	ld	$A[4][3], 0xb8($fp)
	ld	$A[4][4], 0xc0($fp)

	ld	$fp, 8*4($sp)			# pull iotas

	bal	__KeccakF1600

	ld	$fp, 8*0($sp)			# pull A[][]

	sd	$A[4][1], 0xa8($fp)
	sd	$A[4][2], 0xb0($fp)
	sd	$A[4][3], 0xb8($fp)
	sd	$A[4][4], 0xc0($fp)

	ld	$bsz, 8*3($sp)
	ld	$len, 8*2($sp)
	ld	$inp, 8*1($sp)			# pointer to next block

	sltu	$ra, $len, $bsz			# len < bsz?
	beqz	$ra, .Loop_absorb

	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]

	sd	$A[0][0], 0x00($fp)
	sd	$A[0][1], 0x08($fp)
	sd	$A[0][2], 0x10($fp)
	sd	$A[0][3], 0x18($fp)
	sd	$A[0][4], 0x20($fp)
	sd	$A[1][0], 0x28($fp)
	sd	$A[1][1], 0x30($fp)
	sd	$A[1][2], 0x38($fp)
	sd	$A[1][3], 0x40($fp)
	sd	$A[1][4], 0x48($fp)
	sd	$A[2][0], 0x50($fp)
	sd	$A[2][1], 0x58($fp)
	sd	$A[2][2], 0x60($fp)
	sd	$A[2][3], 0x68($fp)
	sd	$A[2][4], 0x70($fp)
	sd	$A[3][0], 0x78($fp)
	sd	$A[3][1], 0x80($fp)
	sd	$A[3][2], 0x88($fp)
	sd	$A[3][3], 0x90($fp)
	sd	$A[3][4], 0x98($fp)
	sd	$A[4][0], 0xa0($fp)

	move	$a0, $len			# return value
	move	$t0, $len

	ld	$ra,  8*19($sp)
	ld	$fp,  8*18($sp)
	ld	$s11, 8*17($sp)
	ld	$s10, 8*16($sp)
	ld	$s9,  8*15($sp)
	ld	$s8,  8*14($sp)
	ld	$s7,  8*13($sp)
	ld	$s6,  8*12($sp)
	ld	$s5,  8*11($sp)
	ld	$s4,  8*10($sp)
___
$code.<<___	if ($flavour =~ /nubi/);
	ld	$s3,  8*9($sp)
	ld	$s2,  8*8($sp)
	ld	$s1,  8*7($sp)
	ld	$s0,  8*6($sp)
	ld	$gp,  8*5($sp)
___
$code.=<<___;
	daddu	$sp, $sp, 8*20
	jr	$ra

.Labsorb_abort:
	move	$a0, $a2			# return value
	move	$t0, $a2
	jr	$ra
.end	SHA3_absorb
___
}
{
my ($A_flat, $out, $len, $bsz) = ($s11, $s10, $s9, $s8);

$code.=<<___;
.globl	SHA3_squeeze
.align	5
.ent	SHA3_squeeze
SHA3_squeeze:
	.frame	$sp, 8*6, $ra
	.mask	0xc0f00000, -8
	.set	noreorder
	dsubu	$sp, $sp, 8*6

	sd	$ra,  8*5($sp)
	sd	$fp,  8*4($sp)
	sd	$s11, 8*3($sp)
	sd	$s10, 8*2($sp)
	sd	$s9,  8*1($sp)
	sd	$s8,  8*0($sp)

	.cplocal $fp
	.cpsetup $pf, $zero, SHA3_squeeze
	.set	reorder

	move	$A_flat, $a0
	move	$out, $a1
	move	$len, $a2
	move	$bsz, $a3

	dla	$fp, iotas

.Loop_squeeze:
	ld	$a4, 0($a0)
	sltu	$ra, $len, 8			# len < 8?
	daddu	$a0, $a0, 8
	bnez	$ra, .Lsqueeze_tail

	dsrl	$a5, $a4, 8
	sb	$a4, 0($out)
	dsrl	$a6, $a4, 16
	sb	$a5, 1($out)
	dsrl	$a7, $a4, 24
	sb	$a6, 2($out)
	dsrl	$at, $a4, 32
	sb	$a7, 3($out)
	dsrl	$a5, $a4, 40
	sb	$at, 4($out)
	dsrl	$a6, $a4, 48
	sb	$a5, 5($out)
	dsrl	$a7, $a4, 56
	sb	$a6, 6($out)
	dsubu	$len, $len, 8			# len -= 8
	sb	$a7, 7($out)
	daddu	$out, $out, 8
	beqz	$len, .Lsqueeze_done

	dsubu	$a3, $a3, 8
	bnez	$a3, .Loop_squeeze

	move	$a0, $A_flat
	bal	KeccakF1600

	move	$a0, $A_flat
	move	$a3, $bsz
	b	.Loop_squeeze

.Lsqueeze_tail:
	sb	$a4, 0($out)
	daddu	$out, $out, 1
	dsubu	$len, $len, 1
	dsrl	$a4, $a4, 8
	bnez	$len, .Lsqueeze_tail

.Lsqueeze_done:
	ld	$ra,  8*5($sp)
	ld	$fp,  8*4($sp)
	ld	$s11, 8*3($sp)
	ld	$s10, 8*2($sp)
	ld	$s9,  8*1($sp)
	ld	$s8,  8*0($sp)
	daddu	$sp, $sp, 8*6
	jr	$ra
.end	SHA3_squeeze
___
}
$code.=<<___;
.rdata
.align 8	# strategic alignment and padding that allows to use
		# address value as loop termination condition...
	.dword	0,0,0,0,0,0,0,0
iotas:
	.dword	0x0000000000000001
	.dword	0x0000000000008082
	.dword	0x800000000000808a
	.dword	0x8000000080008000
	.dword	0x000000000000808b
	.dword	0x0000000080000001
	.dword	0x8000000080008081
	.dword	0x8000000000008009
	.dword	0x000000000000008a
	.dword	0x0000000000000088
	.dword	0x0000000080008009
	.dword	0x000000008000000a
	.dword	0x000000008000808b
	.dword	0x800000000000008b
	.dword	0x8000000000008089
	.dword	0x8000000000008003
	.dword	0x8000000000008002
	.dword	0x8000000000000080
	.dword	0x000000000000800a
	.dword	0x800000008000000a
	.dword	0x8000000080008081
	.dword	0x8000000000008080
	.dword	0x0000000080000001
	.dword	0x8000000080008008
.asciiz "Keccak-1600 absorb and squeeze for MIPS64, CRYPTOGAMS by \@dot-asm"
___
}}} else {{{
######################################################################
# 32-bit code path
#
my @A = map([ 8*$_, 8*($_+1), 8*($_+2), 8*($_+3), 8*($_+4) ], (0,5,10,15,20));

my @C = map("\$$_", (6..15));
my @D = map("\$$_", (16..25));
my @T = map("\$$_", (1..3,31));

$code.=<<___;
#if (defined(_MIPS_ARCH_MIPS32R3) || defined(_MIPS_ARCH_MIPS32R5) || \\
     defined(_MIPS_ARCH_MIPS32R6)) \\
     && !defined(_MIPS_ARCH_MIPS32R2)
# define _MIPS_ARCH_MIPS32R2
#endif

#if defined(__MIPSEB__) && !defined(MIPSEB)
# define MIPSEB
#endif

.text

#if !defined(__mips_eabi) && (!defined(__vxworks) || defined(__pic__))
.option	pic2
#endif
.set	noat
.set	reorder

.align	5
.ent	__KeccakF1600
__KeccakF1600:
	.frame	$sp, 224, $ra
	.mask	0xc0000000, -4
	subu	$sp, $sp, 224
	sw	$ra, 224-4*1($sp)
	sw	$fp, 224-4*2($sp)

	move	$a1, $sp
	lw	@D[0], $A[4][0]+0($a0)
	lw	@D[1], $A[4][0]+4($a0)
	lw	@D[2], $A[4][1]+0($a0)
	lw	@D[3], $A[4][1]+4($a0)
	lw	@D[4], $A[4][2]+0($a0)
	lw	@D[5], $A[4][2]+4($a0)
	lw	@D[6], $A[4][3]+0($a0)
	lw	@D[7], $A[4][3]+4($a0)
	lw	@D[8], $A[4][4]+0($a0)
	lw	@D[9], $A[4][4]+4($a0)
	b	.Loop

.align	4
.Loop:
	lw	@C[0], $A[0][0]+0($a0)
	lw	@C[1], $A[0][0]+4($a0)
	lw	@C[2], $A[0][1]+0($a0)
	lw	@C[3], $A[0][1]+4($a0)
	lw	@C[4], $A[0][2]+0($a0)
	lw	@C[5], $A[0][2]+4($a0)
	lw	@C[6], $A[0][3]+0($a0)
	lw	@C[7], $A[0][3]+4($a0)
	lw	@C[8], $A[0][4]+0($a0)
	lw	@C[9], $A[0][4]+4($a0)
	xor	@C[0], @C[0], @D[0]
	lw	@D[0], $A[1][0]+0($a0)
	xor	@C[1], @C[1], @D[1]
	lw	@D[1], $A[1][0]+4($a0)
	xor	@C[2], @C[2], @D[2]
	lw	@D[2], $A[1][1]+0($a0)
	xor	@C[3], @C[3], @D[3]
	lw	@D[3], $A[1][1]+4($a0)
	xor	@C[4], @C[4], @D[4]
	lw	@D[4], $A[1][2]+0($a0)
	xor	@C[5], @C[5], @D[5]
	lw	@D[5], $A[1][2]+4($a0)
	xor	@C[6], @C[6], @D[6]
	lw	@D[6], $A[1][3]+0($a0)
	xor	@C[7], @C[7], @D[7]
	lw	@D[7], $A[1][3]+4($a0)
	xor	@C[8], @C[8], @D[8]
	lw	@D[8], $A[1][4]+0($a0)
	xor	@C[9], @C[9], @D[9]
	lw	@D[9], $A[1][4]+4($a0)
	xor	@C[0], @C[0], @D[0]
	lw	@D[0], $A[2][0]+0($a0)
	xor	@C[1], @C[1], @D[1]
	lw	@D[1], $A[2][0]+4($a0)
	xor	@C[2], @C[2], @D[2]
	lw	@D[2], $A[2][1]+0($a0)
	xor	@C[3], @C[3], @D[3]
	lw	@D[3], $A[2][1]+4($a0)
	xor	@C[4], @C[4], @D[4]
	lw	@D[4], $A[2][2]+0($a0)
	xor	@C[5], @C[5], @D[5]
	lw	@D[5], $A[2][2]+4($a0)
	xor	@C[6], @C[6], @D[6]
	lw	@D[6], $A[2][3]+0($a0)
	xor	@C[7], @C[7], @D[7]
	lw	@D[7], $A[2][3]+4($a0)
	xor	@C[8], @C[8], @D[8]
	lw	@D[8], $A[2][4]+0($a0)
	xor	@C[9], @C[9], @D[9]
	lw	@D[9], $A[2][4]+4($a0)
	xor	@C[0], @C[0], @D[0]
	lw	@D[0], $A[3][0]+0($a0)
	xor	@C[1], @C[1], @D[1]
	lw	@D[1], $A[3][0]+4($a0)
	xor	@C[2], @C[2], @D[2]
	lw	@D[2], $A[3][1]+0($a0)
	xor	@C[3], @C[3], @D[3]
	lw	@D[3], $A[3][1]+4($a0)
	xor	@C[4], @C[4], @D[4]
	lw	@D[4], $A[3][2]+0($a0)
	xor	@C[5], @C[5], @D[5]
	lw	@D[5], $A[3][2]+4($a0)
	xor	@C[6], @C[6], @D[6]
	lw	@D[6], $A[3][3]+0($a0)
	xor	@C[7], @C[7], @D[7]
	lw	@D[7], $A[3][3]+4($a0)
	xor	@C[8], @C[8], @D[8]
	lw	@D[8], $A[3][4]+0($a0)
	xor	@C[9], @C[9], @D[9]
	lw	@D[9], $A[3][4]+4($a0)
	xor	@C[0], @C[0], @D[0]
	xor	@C[1], @C[1], @D[1]
	xor	@C[2], @C[2], @D[2]
	xor	@C[3], @C[3], @D[3]
	xor	@C[4], @C[4], @D[4]
	xor	@C[5], @C[5], @D[5]
	xor	@C[6], @C[6], @D[6]
	xor	@C[7], @C[7], @D[7]
	xor	@C[8], @C[8], @D[8]
	xor	@C[9], @C[9], @D[9]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@D[2], @C[5], 31
	xor	@D[3], @C[4], @C[1]
	xor	@D[2], @D[2], @C[0]	# D[1] = ROL64(C[2], 1) ^ C[0];

	ror	@D[4], @C[7], 31
	xor	@D[5], @C[6], @C[3]
	xor	@D[4], @D[4], @C[2]	# D[2] = ROL64(C[3], 1) ^ C[1];

	ror	@D[6], @C[9], 31
	xor	@D[7], @C[8], @C[5]
	xor	@D[6], @D[6], @C[4]	# D[3] = ROL64(C[4], 1) ^ C[2];

	ror	@D[8], @C[1], 31
	xor	@D[9], @C[0], @C[7]
	xor	@D[8], @D[8], @C[6]	# D[4] = ROL64(C[0], 1) ^ C[3];

	ror	@D[0], @C[3], 31
	xor	@D[1], @C[2], @C[9]
	xor	@D[0], @D[0], @C[8]	# D[0] = ROL64(C[1], 1) ^ C[4];
#else
	srl	@T[0], @C[5], 31
	addu	@D[2], @C[5], @C[5]
	or	@D[2], @D[2], @T[0]
	xor	@D[3], @C[4], @C[1]
	xor	@D[2], @D[2], @C[0]	# D[1] = ROL64(C[2], 1) ^ C[0];

	srl	@T[1], @C[7], 31
	addu	@D[4], @C[7], @C[7]
	or	@D[4], @D[4], @T[1]
	xor	@D[5], @C[6], @C[3]
	xor	@D[4], @D[4], @C[2]	# D[2] = ROL64(C[3], 1) ^ C[1];

	srl	@T[0], @C[9], 31
	addu	@D[6], @C[9], @C[9]
	or	@D[6], @D[6], @T[0]
	xor	@D[7], @C[8], @C[5]
	xor	@D[6], @D[6], @C[4]	# D[3] = ROL64(C[4], 1) ^ C[2];

	srl	@T[1], @C[1], 31
	addu	@D[8], @C[1], @C[1]
	or	@D[8], @D[8], @T[1]
	xor	@D[9], @C[0], @C[7]
	xor	@D[8], @D[8], @C[6]	# D[4] = ROL64(C[0], 1) ^ C[3];

	srl	@T[0], @C[3], 31
	addu	@D[0], @C[3], @C[3]
	or	@D[0], @D[0], @T[0]
	xor	@D[1], @C[2], @C[9]
	xor	@D[0], @D[0], @C[8]	# D[0] = ROL64(C[1], 1) ^ C[4];
#endif

	lw	@C[0], $A[0][0]+0($a0)
	lw	@C[1], $A[0][0]+4($a0)
	lw	@C[2], $A[1][1]+0($a0)
	lw	@C[3], $A[1][1]+4($a0)
	xor	@C[0], @C[0], @D[0]
	lw	@C[4], $A[2][2]+4($a0)	# flip order
	xor	@C[1], @C[1], @D[1]
	lw	@C[5], $A[2][2]+0($a0)
	xor	@C[2], @C[2], @D[2]
	lw	@C[6], $A[3][3]+4($a0)	# flip order
	xor	@C[3], @C[3], @D[3]
	lw	@C[7], $A[3][3]+0($a0)
	xor	@C[4], @C[4], @D[5]	# flip order
	lw	@C[8], $A[4][4]+0($a0)
	xor	@C[5], @C[5], @D[4]
	lw	@C[9], $A[4][4]+4($a0)
	xor	@C[6], @C[6], @D[7]	# flip order
	 lw	@T[2], 0($fp)		# *iotas++
	xor	@C[7], @C[7], @D[6]
	 lw	@T[3], 4($fp)
	 addu	$fp, $fp, 8
	xor	@C[8], @C[8], @D[8]
	xor	@C[9], @C[9], @D[9]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@C[2], @C[2], 32-22	# rhotates[1][1] == 44
	ror	@C[3], @C[3], 32-22
	ror	@C[4], @C[4], 31-21	# rhotates[2][2] == 43
	ror	@C[5], @C[5], 32-21
	ror	@C[6], @C[6], 31-10	# rhotates[3][3] == 21
	ror	@C[7], @C[7], 32-10
	ror	@C[8], @C[8], 32-7	# rhotates[4][4] == 14
	ror	@C[9], @C[9], 32-7
#else
	srl	@T[0], @C[2], 32-22
	sll	@C[2], @C[2], 22
	srl	@T[1], @C[3], 32-22
	sll	@C[3], @C[3], 22
	or	@C[2], @C[2], @T[0]
	or	@C[3], @C[3], @T[1]
	srl	@T[0], @C[4], 31-21
	sll	@C[4], @C[4], 22
	srl	@T[1], @C[5], 32-21
	sll	@C[5], @C[5], 21
	or	@C[4], @C[4], @T[0]
	or	@C[5], @C[5], @T[1]
	srl	@T[0], @C[6], 31-10
	sll	@C[6], @C[6], 11
	srl	@T[1], @C[7], 32-10
	sll	@C[7], @C[7], 10
	or	@C[6], @C[6], @T[0]
	or	@C[7], @C[7], @T[1]
	srl	@T[0], @C[8], 32-7
	sll	@C[8], @C[8], 7
	srl	@T[1], @C[9], 32-7
	sll	@C[9], @C[9], 7
	or	@C[8], @C[8], @T[0]
	or	@C[9], @C[9], @T[1]
#endif

	or	@T[0], @C[2], @C[4]
	or	@T[1], @C[3], @C[5]
	xor	@T[0], @T[0], @T[2]	# ^= iotas[i]
	not	@T[2], @C[4]
	xor	@T[1], @T[1], @T[3]
	not	@T[3], @C[5]
	or	@T[2], @T[2], @C[6]
	or	@T[3], @T[3], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	sw	@T[0], $A[0][0]+0($a1)	# R[0][0] = C[0] ^ ( C[1] | C[2]);
	and	@T[0], @C[6], @C[8]
	sw	@T[1], $A[0][0]+4($a1)
	and	@T[1], @C[7], @C[9]
	sw	@T[2], $A[0][1]+0($a1)	# R[0][1] = C[1] ^ (~C[2] | C[3]);
	or	@T[2], @C[8], @C[0]
	sw	@T[3], $A[0][1]+4($a1)
	or	@T[3], @C[9], @C[1]
	xor	@T[0], @T[0], @C[4]
	xor	@T[1], @T[1], @C[5]
	xor	@T[2], @T[2], @C[6]
	xor	@T[3], @T[3], @C[7]
	sw	@T[0], $A[0][2]+0($a1)	# R[0][2] = C[2] ^ ( C[3] & C[4]);
	and	@C[0], @C[0], @C[2]
	sw	@T[1], $A[0][2]+4($a1)
	and	@C[1], @C[1], @C[3]
	sw	@T[2], $A[0][3]+0($a1)	# R[0][3] = C[3] ^ ( C[4] | C[0]);
	xor	@C[8], @C[8], @C[0]
	sw	@T[3], $A[0][3]+4($a1)
	xor	@C[9], @C[9], @C[1]
	sw	@C[8], $A[0][4]+0($a1)	# R[0][4] = C[4] ^ ( C[0] & C[1]);
	sw	@C[9], $A[0][4]+4($a1)

	lw	@C[0], $A[0][3]+0($a0)
	lw	@C[1], $A[0][3]+4($a0)
	lw	@C[2], $A[1][4]+0($a0)
	lw	@C[3], $A[1][4]+4($a0)
	xor	@C[0], @C[0], @D[6]
	lw	@C[4], $A[2][0]+4($a0)	# flip order
	xor	@C[1], @C[1], @D[7]
	lw	@C[5], $A[2][0]+0($a0)
	xor	@C[2], @C[2], @D[8]
	lw	@C[6], $A[3][1]+4($a0)	# flip order
	xor	@C[3], @C[3], @D[9]
	lw	@C[7], $A[3][1]+0($a0)
	xor	@C[4], @C[4], @D[1]	# flip order
	lw	@C[8], $A[4][2]+4($a0)	# flip order
	xor	@C[5], @C[5], @D[0]
	lw	@C[9], $A[4][2]+0($a0)
	xor	@C[6], @C[6], @D[3]	# flip order
	xor	@C[7], @C[7], @D[2]
	xor	@C[8], @C[8], @D[5]	# flip order
	xor	@C[9], @C[9], @D[4]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@C[0], @C[0], 32-14	# rhotates[0][3] == 28
	ror	@C[1], @C[1], 32-14
	ror	@C[2], @C[2], 32-10	# rhotates[1][4] == 20
	ror	@C[3], @C[3], 32-10
	ror	@C[4], @C[4], 31-1	# rhotates[2][0] == 3
	ror	@C[5], @C[5], 32-1
	ror	@C[6], @C[6], 31-22	# rhotates[3][1] == 45
	ror	@C[7], @C[7], 32-22
	ror	@C[8], @C[8], 31-30	# rhotates[4][2] == 61
	ror	@C[9], @C[9], 32-30
#else
	srl	@T[0], @C[0], 32-14
	sll	@C[0], @C[0], 14
	srl	@T[1], @C[1], 32-14
	sll	@C[1], @C[1], 14
	or	@C[0], @C[0], @T[0]
	or	@C[1], @C[1], @T[1]
	srl	@T[0], @C[2], 32-10
	sll	@C[2], @C[2], 10
	srl	@T[1], @C[3], 32-10
	sll	@C[3], @C[3], 10
	or	@C[2], @C[2], @T[0]
	or	@C[3], @C[3], @T[1]
	srl	@T[0], @C[4], 31-1
	sll	@C[4], @C[4], 2
	srl	@T[1], @C[5], 32-1
	sll	@C[5], @C[5], 1
	or	@C[4], @C[4], @T[0]
	or	@C[5], @C[5], @T[1]
	srl	@T[0], @C[6], 31-22
	sll	@C[6], @C[6], 23
	srl	@T[1], @C[7], 32-22
	sll	@C[7], @C[7], 22
	or	@C[6], @C[6], @T[0]
	or	@C[7], @C[7], @T[1]
	srl	@T[0], @C[8], 31-30
	sll	@C[8], @C[8], 31
	srl	@T[1], @C[9], 32-30
	sll	@C[9], @C[9], 30
	or	@C[8], @C[8], @T[0]
	or	@C[9], @C[9], @T[1]
#endif

	or	@T[0], @C[2], @C[4]
	or	@T[1], @C[3], @C[5]
	and	@T[2], @C[4], @C[6]
	and	@T[3], @C[5], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	sw	@T[0], $A[1][0]+0($a1)	# R[1][0] = C[0] ^ ( C[1] |  C[2]);
	not	@T[0], @C[8]
	sw	@T[1], $A[1][0]+4($a1)
	not	@T[1], @C[9]
	sw	@T[2], $A[1][1]+0($a1)	# R[1][1] = C[1] ^ ( C[2] &  C[3]);
	or	@T[0], @T[0], @C[6]
	sw	@T[3], $A[1][1]+4($a1)
	or	@T[1], @T[1], @C[7]
	or	@T[2], @C[8], @C[0]
	or	@T[3], @C[9], @C[1]
	xor	@T[0], @T[0], @C[4]
	xor	@T[1], @T[1], @C[5]
	xor	@T[2], @T[2], @C[6]
	xor	@T[3], @T[3], @C[7]
	sw	@T[0], $A[1][2]+0($a1)	# R[1][2] = C[2] ^ ( C[3] | ~C[4]);
	and	@C[0], @C[0], @C[2]
	sw	@T[1], $A[1][2]+4($a1)
	and	@C[1], @C[1], @C[3]
	sw	@T[2], $A[1][3]+0($a1)	# R[1][3] = C[3] ^ ( C[4] |  C[0]);
	xor	@C[8], @C[8], @C[0]
	sw	@T[3], $A[1][3]+4($a1)
	xor	@C[9], @C[9], @C[1]
	sw	@C[8], $A[1][4]+0($a1)	# R[1][4] = C[4] ^ ( C[0] &  C[1]);
	sw	@C[9], $A[1][4]+4($a1)

	lw	@C[0], $A[0][1]+4($a0)	# flip order
	lw	@C[1], $A[0][1]+0($a0)
	lw	@C[2], $A[1][2]+0($a0)
	lw	@C[3], $A[1][2]+4($a0)
	xor	@C[0], @C[0], @D[3]	# flip order
	lw	@C[4], $A[2][3]+4($a0)	# flip order
	xor	@C[1], @C[1], @D[2]
	lw	@C[5], $A[2][3]+0($a0)
	xor	@C[2], @C[2], @D[4]
	lw	@C[6], $A[3][4]+0($a0)
	xor	@C[3], @C[3], @D[5]
	lw	@C[7], $A[3][4]+4($a0)
	xor	@C[4], @C[4], @D[7]	# flip order
	lw	@C[8], $A[4][0]+0($a0)
	xor	@C[5], @C[5], @D[6]
	lw	@C[9], $A[4][0]+4($a0)
	xor	@C[6], @C[6], @D[8]
	xor	@C[7], @C[7], @D[9]
	xor	@C[8], @C[8], @D[0]
	xor	@C[9], @C[9], @D[1]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@C[0], @C[0], 31-0	# rhotates[0][1] == 1
	#ror	@C[1], @C[1], 32-0
	ror	@C[2], @C[2], 32-3	# rhotates[1][2] == 6
	ror	@C[3], @C[3], 32-3
	ror	@C[4], @C[4], 31-12	# rhotates[2][3] == 25
	ror	@C[5], @C[5], 32-12
	ror	@C[6], @C[6], 32-4	# rhotates[3][4] == 8
	ror	@C[7], @C[7], 32-4
	ror	@C[8], @C[8], 32-9	# rhotates[4][0] == 18
	ror	@C[9], @C[9], 32-9
#else
	srl	@T[0], @C[0], 31-0
	sll	@C[0], @C[0], 1
	#srl	@T[1], @C[1], 32-0
	#sll	@C[1], @C[1], 0
	or	@C[0], @C[0], @T[0]
	#or	@C[1], @C[1], @T[1]
	srl	@T[0], @C[2], 32-3
	sll	@C[2], @C[2], 3
	srl	@T[1], @C[3], 32-3
	sll	@C[3], @C[3], 3
	or	@C[2], @C[2], @T[0]
	or	@C[3], @C[3], @T[1]
	srl	@T[0], @C[4], 31-12
	sll	@C[4], @C[4], 13
	srl	@T[1], @C[5], 32-12
	sll	@C[5], @C[5], 12
	or	@C[4], @C[4], @T[0]
	or	@C[5], @C[5], @T[1]
	srl	@T[0], @C[6], 32-4
	sll	@C[6], @C[6], 4
	srl	@T[1], @C[7], 32-4
	sll	@C[7], @C[7], 4
	or	@C[6], @C[6], @T[0]
	or	@C[7], @C[7], @T[1]
	srl	@T[0], @C[8], 32-9
	sll	@C[8], @C[8], 9
	srl	@T[1], @C[9], 32-9
	sll	@C[9], @C[9], 9
	or	@C[8], @C[8], @T[0]
	or	@C[9], @C[9], @T[1]
#endif

	or	@T[0], @C[2], @C[4]
	or	@T[1], @C[3], @C[5]
	and	@T[2], @C[4], @C[6]
	not	@C[6], @C[6]
	and	@T[3], @C[5], @C[7]
	not	@C[7], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	sw	@T[0], $A[2][0]+0($a1)	# R[2][0] =  C[0] ^ ( C[1] | C[2]);
	and	@T[0], @C[6], @C[8]
	sw	@T[1], $A[2][0]+4($a1)
	and	@T[1], @C[7], @C[9]
	sw	@T[2], $A[2][1]+0($a1)	# R[2][1] =  C[1] ^ ( C[2] & C[3]);
	or	@T[2], @C[8], @C[0]
	sw	@T[3], $A[2][1]+4($a1)
	or	@T[3], @C[9], @C[1]
	xor	@T[0], @T[0], @C[4]
	xor	@T[1], @T[1], @C[5]
	xor	@T[2], @T[2], @C[6]
	xor	@T[3], @T[3], @C[7]
	sw	@T[0], $A[2][2]+0($a1)	# R[2][2] =  C[2] ^ (~C[3] & C[4]);
	and	@C[0], @C[0], @C[2]
	sw	@T[1], $A[2][2]+4($a1)
	and	@C[1], @C[1], @C[3]
	sw	@T[2], $A[2][3]+0($a1)	# R[2][3] = ~C[3] ^ ( C[4] | C[0]);
	xor	@C[8], @C[8], @C[0]
	sw	@T[3], $A[2][3]+4($a1)
	xor	@C[9], @C[9], @C[1]
	sw	@C[8], $A[2][4]+0($a1)	# R[2][4] =  C[4] ^ ( C[0] & C[1]);
	sw	@C[9], $A[2][4]+4($a1)

	lw	@C[0], $A[0][4]+4($a0)	# flip order
	lw	@C[1], $A[0][4]+0($a0)
	lw	@C[2], $A[1][0]+0($a0)
	lw	@C[3], $A[1][0]+4($a0)
	xor	@C[0], @C[0], @D[9]	# flip order
	lw	@C[4], $A[2][1]+0($a0)
	xor	@C[1], @C[1], @D[8]
	lw	@C[5], $A[2][1]+4($a0)
	xor	@C[2], @C[2], @D[0]
	lw	@C[6], $A[3][2]+4($a0)	# flip order
	xor	@C[3], @C[3], @D[1]
	lw	@C[7], $A[3][2]+0($a0)
	xor	@C[4], @C[4], @D[2]
	lw	@C[8], $A[4][3]+0($a0)
	xor	@C[5], @C[5], @D[3]
	lw	@C[9], $A[4][3]+4($a0)
	xor	@C[6], @C[6], @D[5]	# flip order
	xor	@C[7], @C[7], @D[4]
	xor	@C[8], @C[8], @D[6]
	xor	@C[9], @C[9], @D[7]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@C[0], @C[0], 31-13	# rhotates[0][4] == 27
	ror	@C[1], @C[1], 32-13
	ror	@C[2], @C[2], 32-18	# rhotates[1][0] == 36
	ror	@C[3], @C[3], 32-18
	ror	@C[4], @C[4], 32-5	# rhotates[2][1] == 10
	ror	@C[5], @C[5], 32-5
	ror	@C[6], @C[6], 31-7	# rhotates[3][2] == 15
	ror	@C[7], @C[7], 32-7
	ror	@C[8], @C[8], 32-28	# rhotates[4][3] == 56
	ror	@C[9], @C[9], 32-28
#else
	srl	@T[0], @C[0], 31-13
	sll	@C[0], @C[0], 14
	srl	@T[1], @C[1], 32-13
	sll	@C[1], @C[1], 13
	or	@C[0], @C[0], @T[0]
	or	@C[1], @C[1], @T[1]
	srl	@T[0], @C[2], 32-18
	sll	@C[2], @C[2], 18
	srl	@T[1], @C[3], 32-18
	sll	@C[3], @C[3], 18
	or	@C[2], @C[2], @T[0]
	or	@C[3], @C[3], @T[1]
	srl	@T[0], @C[4], 32-5
	sll	@C[4], @C[4], 5
	srl	@T[1], @C[5], 32-5
	sll	@C[5], @C[5], 5
	or	@C[4], @C[4], @T[0]
	or	@C[5], @C[5], @T[1]
	srl	@T[0], @C[6], 31-7
	sll	@C[6], @C[6], 8
	srl	@T[1], @C[7], 32-7
	sll	@C[7], @C[7], 7
	or	@C[6], @C[6], @T[0]
	or	@C[7], @C[7], @T[1]
	srl	@T[0], @C[8], 32-28
	sll	@C[8], @C[8], 28
	srl	@T[1], @C[9], 32-28
	sll	@C[9], @C[9], 28
	or	@C[8], @C[8], @T[0]
	or	@C[9], @C[9], @T[1]
#endif

	and	@T[0], @C[2], @C[4]
	and	@T[1], @C[3], @C[5]
	or	@T[2], @C[4], @C[6]
	not	@C[6], @C[6]
	or	@T[3], @C[5], @C[7]
	not	@C[7], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	sw	@T[0], $A[3][0]+0($a1)	# R[3][0] =  C[0] ^ ( C[1] & C[2]);
	or	@T[0], @C[6], @C[8]
	sw	@T[1], $A[3][0]+4($a1)
	or	@T[1], @C[7], @C[9]
	sw	@T[2], $A[3][1]+0($a1)	# R[3][1] =  C[1] ^ ( C[2] | C[3]);
	and	@T[2], @C[8], @C[0]
	sw	@T[3], $A[3][1]+4($a1)
	and	@T[3], @C[9], @C[1]
	xor	@T[0], @T[0], @C[4]
	xor	@T[1], @T[1], @C[5]
	xor	@T[2], @T[2], @C[6]
	xor	@T[3], @T[3], @C[7]
	sw	@T[0], $A[3][2]+0($a1)	# R[3][2] =  C[2] ^ (~C[3] | C[4]);
	or	@C[0], @C[0], @C[2]
	sw	@T[1], $A[3][2]+4($a1)
	or	@C[1], @C[1], @C[3]
	sw	@T[2], $A[3][3]+0($a1)	# R[3][3] = ~C[3] ^ ( C[4] & C[0]);
	xor	@C[8], @C[8], @C[0]
	sw	@T[3], $A[3][3]+4($a1)
	xor	@C[9], @C[9], @C[1]
	sw	@C[8], $A[3][4]+0($a1)	# R[3][4] =  C[4] ^ ( C[0] | C[1]);
	sw	@C[9], $A[3][4]+4($a1)

	lw	@C[0], $A[0][2]+0($a0)
	lw	@C[1], $A[0][2]+4($a0)
	lw	@C[2], $A[1][3]+4($a0)	# flip order
	 xor	$a1, $a1, $a0		# xchg	$a0, $a1
	lw	@C[3], $A[1][3]+0($a0)
	xor	@C[0], @C[0], @D[4]
	lw	@C[4], $A[2][4]+4($a0)	# flip order
	xor	@C[1], @C[1], @D[5]
	lw	@C[5], $A[2][4]+0($a0)
	xor	@C[2], @C[2], @D[7]	# flip order
	lw	@C[6], $A[3][0]+4($a0)	# flip order
	xor	@C[3], @C[3], @D[6]
	lw	@C[7], $A[3][0]+0($a0)
	xor	@C[4], @C[4], @D[9]	# flip order
	lw	@C[8], $A[4][1]+0($a0)
	xor	@C[5], @C[5], @D[8]
	lw	@C[9], $A[4][1]+4($a0)
	 xor	$a0, $a0, $a1
	xor	@C[6], @C[6], @D[1]	# flip order
	xor	@C[7], @C[7], @D[0]
	 xor	$a1, $a1, $a0
	xor	@C[8], @C[8], @D[2]
	xor	@C[9], @C[9], @D[3]

#ifdef	_MIPS_ARCH_MIPS32R2
	ror	@C[0], @C[0], 32-31	# rhotates[0][2] == 62
	ror	@C[1], @C[1], 32-31
	ror	@C[2], @C[2], 31-27	# rhotates[1][3] == 55
	ror	@C[3], @C[3], 32-27
	ror	@C[4], @C[4], 31-19	# rhotates[2][4] == 39
	ror	@C[5], @C[5], 32-19
	ror	@C[6], @C[6], 31-20	# rhotates[3][0] == 41
	ror	@C[7], @C[7], 32-20
	ror	@C[8], @C[8], 32-1	# rhotates[4][1] == 2
	ror	@C[9], @C[9], 32-1
#else
	srl	@T[0], @C[0], 32-31
	sll	@C[0], @C[0], 31
	srl	@T[1], @C[1], 32-31
	sll	@C[1], @C[1], 31
	or	@C[0], @C[0], @T[0]
	or	@C[1], @C[1], @T[1]
	srl	@T[0], @C[2], 31-27
	sll	@C[2], @C[2], 28
	srl	@T[1], @C[3], 32-27
	sll	@C[3], @C[3], 27
	or	@C[2], @C[2], @T[0]
	or	@C[3], @C[3], @T[1]
	srl	@T[0], @C[4], 31-19
	sll	@C[4], @C[4], 20
	srl	@T[1], @C[5], 32-19
	sll	@C[5], @C[5], 19
	or	@C[4], @C[4], @T[0]
	or	@C[5], @C[5], @T[1]
	srl	@T[0], @C[6], 31-20
	sll	@C[6], @C[6], 21
	srl	@T[1], @C[7], 32-20
	sll	@C[7], @C[7], 20
	or	@C[6], @C[6], @T[0]
	or	@C[7], @C[7], @T[1]
	srl	@T[0], @C[8], 32-1
	sll	@C[8], @C[8], 1
	srl	@T[1], @C[9], 32-1
	sll	@C[9], @C[9], 1
	or	@C[8], @C[8], @T[0]
	or	@C[9], @C[9], @T[1]
#endif

	not	@T[2], @C[2]
	not	@T[3], @C[3]
	and	@D[0], @T[2], @C[4]
	and	@D[1], @T[3], @C[5]
	or	@D[2], @C[4], @C[6]
	or	@D[3], @C[5], @C[7]
	xor	@D[0], @D[0], @C[0]
	xor	@D[1], @D[1], @C[1]
	xor	@D[2], @D[2], @T[2]
	xor	@D[3], @D[3], @T[3]
	sw	@D[0], $A[4][0]+0($a0)	# R[4][0] =  C[0] ^ (~C[1] & C[2]);
	and	@D[4], @C[6], @C[8]
	sw	@D[1], $A[4][0]+4($a0)
	and	@D[5], @C[7], @C[9]
	sw	@D[2], $A[4][1]+0($a0)	# R[4][1] = ~C[1] ^ ( C[2] | C[3]);
	or	@D[6], @C[8], @C[0]
	sw	@D[3], $A[4][1]+4($a0)
	or	@D[7], @C[9], @C[1]
	xor	@D[4], @D[4], @C[4]
	xor	@D[5], @D[5], @C[5]
	xor	@D[6], @D[6], @C[6]
	xor	@D[7], @D[7], @C[7]
	sw	@D[4], $A[4][2]+0($a0)	# R[4][2] =  C[2] ^ ( C[3] & C[4]);
	and	@C[0], @C[0], @C[2]
	sw	@D[5], $A[4][2]+4($a0)
	and	@C[1], @C[1], @C[3]
	sw	@D[6], $A[4][3]+0($a0)	# R[4][3] =  C[3] ^ ( C[4] | C[0]);
	xor	@D[8], @C[8], @C[0]
	sw	@D[7], $A[4][3]+4($a0)
	xor	@D[9], @C[9], @C[1]
	sw	@D[8], $A[4][4]+0($a0)	# R[4][4] =  C[4] ^ ( C[0] & C[1]);
	andi	@T[0], $fp, 0xff
	sw	@D[9], $A[4][4]+4($a0)
	bnez	@T[0], .Loop

	lw	$ra, 224-4*1($sp)
	lw	$fp, 224-4*2($sp)
	addu	$sp, $sp, 224
	jr	$ra
.end	__KeccakF1600

.align	5
.ent	KeccakF1600
KeccakF1600:
	.frame	$sp, 4*16, $ra
	.mask	$SAVED_REGS_MASK, -4
	.set	noreorder
	#.cpload $pf
	subu	$sp,  $sp, 4*16
	sw	$ra,  4*15($sp)
	sw	$fp,  4*14($sp)
	sw	$s11, 4*13($sp)
	sw	$s10, 4*12($sp)
	sw	$s9,  4*11($sp)
	sw	$s8,  4*10($sp)
	sw	$s7,  4*9($sp)
	sw	$s6,  4*8($sp)
	sw	$s5,  4*7($sp)
	sw	$s4,  4*6($sp)
___
$code.=<<___	if ($flavour =~ /nubi/);
	sw	$s3,  4*5($sp)
	sw	$s2,  4*4($sp)
	sw	$s1,  4*3($sp)
	sw	$s0,  4*2($sp)
	sw	$gp,  4*1($sp)
___
$code.=<<___;
	.set	reorder
	#la	$fp, iotas		# caller's responsibility

	lw	$s0, $A[0][1]+0($a0)
	lw	$s1, $A[0][1]+4($a0)
	lw	$s2, $A[0][2]+0($a0)
	lw	$s3, $A[0][2]+4($a0)
	lw	$s4, $A[1][3]+0($a0)
	lw	$s5, $A[1][3]+4($a0)
	not	$s0, $s0
	lw	$s6, $A[2][2]+0($a0)
	not	$s1, $s1
	lw	$s7, $A[2][2]+4($a0)
	not	$s2, $s2
	lw	$a4, $A[3][2]+0($a0)
	not	$s3, $s3
	lw	$a5, $A[3][2]+4($a0)
	not	$s4, $s4
	lw	$a6, $A[4][0]+0($a0)
	not	$s5, $s5
	lw	$a7, $A[4][0]+4($a0)
	sw	$s0, $A[0][1]+0($a0)
	not	$s6, $s6
	sw	$s1, $A[0][1]+4($a0)
	not	$s7, $s7
	sw	$s2, $A[0][2]+0($a0)
	not	$a4, $a4
	sw	$s3, $A[0][2]+4($a0)
	not	$a5, $a5
	sw	$s4, $A[1][3]+0($a0)
	not	$a6, $a6
	sw	$s5, $A[1][3]+4($a0)
	not	$a7, $a7
	sw	$s6, $A[2][2]+0($a0)
	sw	$s7, $A[2][2]+4($a0)
	sw	$a4, $A[3][2]+0($a0)
	sw	$a5, $A[3][2]+4($a0)
	sw	$a6, $A[4][0]+0($a0)
	sw	$a7, $A[4][0]+4($a0)

	bal	__KeccakF1600

	lw	$s0, $A[0][1]+0($a0)
	lw	$s1, $A[0][1]+4($a0)
	lw	$s2, $A[0][2]+0($a0)
	lw	$s3, $A[0][2]+4($a0)
	lw	$s4, $A[1][3]+0($a0)
	lw	$s5, $A[1][3]+4($a0)
	not	$s0, $s0
	lw	$s6, $A[2][2]+0($a0)
	not	$s1, $s1
	lw	$s7, $A[2][2]+4($a0)
	not	$s2, $s2
	lw	$a4, $A[3][2]+0($a0)
	not	$s3, $s3
	lw	$a5, $A[3][2]+4($a0)
	not	$s4, $s4
	lw	$a6, $A[4][0]+0($a0)
	not	$s5, $s5
	lw	$a7, $A[4][0]+4($a0)
	sw	$s0, $A[0][1]+0($a0)
	not	$s6, $s6
	sw	$s1, $A[0][1]+4($a0)
	not	$s7, $s7
	sw	$s2, $A[0][2]+0($a0)
	not	$a4, $a4
	sw	$s3, $A[0][2]+4($a0)
	not	$a5, $a5
	sw	$s4, $A[1][3]+0($a0)
	not	$a6, $a6
	sw	$s5, $A[1][3]+4($a0)
	not	$a7, $a7
	sw	$s6, $A[2][2]+0($a0)
	sw	$s7, $A[2][2]+4($a0)
	sw	$a4, $A[3][2]+0($a0)
	sw	$a5, $A[3][2]+4($a0)
	sw	$a6, $A[4][0]+0($a0)
	sw	$a7, $A[4][0]+4($a0)

	lw	$ra,  4*15($sp)
	lw	$fp,  4*14($sp)
	lw	$s11, 4*13($sp)
	lw	$s10, 4*12($sp)
	lw	$s9,  4*11($sp)
	lw	$s8,  4*10($sp)
	lw	$s7,  4*9($sp)
	lw	$s6,  4*8($sp)
	lw	$s5,  4*7($sp)
	lw	$s4,  4*6($sp)
___
$code.<<___	if ($flavour =~ /nubi/);
	lw	$s3,  4*5($sp)
	lw	$s2,  4*4($sp)
	lw	$s1,  4*3($sp)
	lw	$s0,  4*2($sp)
	lw	$gp,  4*1($sp)
___
$code.=<<___;
	addu	$sp,  $sp, 4*16
	jr	$ra
.end	KeccakF1600
___
{
my ($A_flat, $inp, $len, $bsz) = ($ra, $a1, $a2, $a3);
$code.=<<___;
.globl	SHA3_absorb
.align	5
.ent	SHA3_absorb
SHA3_absorb:
	.frame	$sp, 4*20, $ra
	.mask	$SAVED_REGS_MASK, -4
	.set	noreorder
	.cpload	$pf
	sltu	$at, $len, $bsz		# len < bsz?
	bnez	$at, .Labsorb_abort
	subu	$sp,  $sp, 4*20
	sw	$ra,  4*19($sp)
	sw	$fp,  4*18($sp)
	sw	$s11, 4*17($sp)
	sw	$s10, 4*16($sp)
	sw	$s9,  4*15($sp)
	sw	$s8,  4*14($sp)
	sw	$s7,  4*13($sp)
	sw	$s6,  4*12($sp)
	sw	$s5,  4*11($sp)
	sw	$s4,  4*10($sp)
___
$code.=<<___	if ($flavour =~ /nubi/);
	sw	$s3,  4*9($sp)
	sw	$s2,  4*8($sp)
	sw	$s1,  4*7($sp)
	sw	$s0,  4*6($sp)
	sw	$gp,  4*5($sp)
___
$code.=<<___;
	.set	reorder
	la	$fp, iotas

	lw	$s0, $A[0][1]+0($a0)
	lw	$s1, $A[0][1]+4($a0)
	lw	$s2, $A[0][2]+0($a0)
	lw	$s3, $A[0][2]+4($a0)
	lw	$s4, $A[1][3]+0($a0)
	lw	$s5, $A[1][3]+4($a0)
	not	$s0, $s0
	lw	$s6, $A[2][2]+0($a0)
	not	$s1, $s1
	lw	$s7, $A[2][2]+4($a0)
	not	$s2, $s2
	lw	$a4, $A[3][2]+0($a0)
	not	$s3, $s3
	lw	$a5, $A[3][2]+4($a0)
	not	$s4, $s4
	lw	$a6, $A[4][0]+0($a0)
	not	$s5, $s5
	lw	$a7, $A[4][0]+4($a0)
	sw	$s0, $A[0][1]+0($a0)
	not	$s6, $s6
	sw	$s1, $A[0][1]+4($a0)
	not	$s7, $s7
	sw	$s2, $A[0][2]+0($a0)
	not	$a4, $a4
	sw	$s3, $A[0][2]+4($a0)
	not	$a5, $a5
	sw	$s4, $A[1][3]+0($a0)
	not	$a6, $a6
	sw	$s5, $A[1][3]+4($a0)
	not	$a7, $a7
	sw	$s6, $A[2][2]+0($a0)
	sw	$s7, $A[2][2]+4($a0)
	sw	$a4, $A[3][2]+0($a0)
	sw	$a5, $A[3][2]+4($a0)
	sw	$a6, $A[4][0]+0($a0)
	sw	$a7, $A[4][0]+4($a0)

	sw	$bsz, 4*2($sp)
	b	.Loop_absorb

.align	4
.Loop_absorb:
	subu	$t1, $len, $bsz
	addu	$t2, $inp, $bsz		# next input block
	sw	$t1, 4*1($sp)
	sw	$t2, 4*0($sp)
	move	$A_flat, $a0
	lui	$s0, 0x5555
	lui	$s1, 0x3333
	lui	$s2, 0x0f0f
	lui	$s3, 0x00ff
	ori	$s0, 0x5555		# 0x55555555
	ori	$s1, 0x3333		# 0x33333333
	ori	$s2, 0x0f0f		# 0x0f0f0f0f
	ori	$s3, 0x00ff		# 0x00ff00ff
	sll	$s4, $s0, 1		# 0xaaaaaaaa
	sll	$s5, $s1, 2		# 0xcccccccc
	sll	$s6, $s2, 4		# 0xf0f0f0f0
	sll	$s7, $s3, 8		# 0xff00ff00
	lui	$s8, 0xffff		# 0xffff0000

.Loop_block:
#if !defined(MIPSEB) && !defined(_MIPS_ARCH_MIPS32R6)
	lwl	$a4, 0+3($inp)		# load [misaligned] input
	lwl	$a5, 4+3($inp)
	lwr	$a4, 0+0($inp)
	lwr	$a5, 4+0($inp)
#else
	lbu	$a4, 0($inp)
	lbu	$a5, 4($inp)
	lbu	$a6, 1($inp)
	lbu	$a7, 5($inp)
	lbu	$at, 2($inp)
	lbu	$t0, 6($inp)
	sll	$a6, $a6, 8
	lbu	$t1, 3($inp)
	sll	$a7, $a7, 8
	lbu	$t2, 7($inp)
	sll	$at, $at, 16
	or	$a4, $a4, $a6
	sll	$t0, $t0, 16
	or	$a5, $a5, $a7
	sll	$t1, $t1, 24
	or	$a4, $a4, $at
	sll	$t2, $t2, 24
	or	$a5, $a5, $t0
	or	$a4, $a4, $t1
	or	$a5, $a5, $t2
#endif
	addu	$inp, $inp, 8

	lw	$s10, 0($A_flat)
	lw	$s11, 4($A_flat)

	and	$t0, $a4, $s0		# t0 = lo & 0x55555555;
	 and	$t1, $a5, $s0		# t1 = hi & 0x55555555;
	srl	$at, $t0, 1
	 srl	$t2, $t1, 1
	or	$t0, $t0, $at		# t0 |= t0 >> 1;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 1;
	and	$t0, $t0, $s1		# t0 &= 0x33333333;
	 and	$t1, $t1, $s1		# t1 &= 0x33333333;
	srl	$at, $t0, 2
	 srl	$t2, $t1, 2
	or	$t0, $t0, $at		# t0 |= t0 >> 2;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 2;
	and	$t0, $t0, $s2		# t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s2		# t1 &= 0x0f0f0f0f;
	srl	$at, $t0, 4
	 srl	$t2, $t1, 4
	or	$t0, $t0, $at		# t0 |= t0 >> 4;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 4;
	and	$t0, $t0, $s3		# t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s3		# t1 &= 0x00ff00ff;
	srl	$at, $t0, 8
	 srl	$t2, $t1, 8
	or	$t0, $t0, $at		# t0 |= t0 >> 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 8;
	andi	$t0, $t0, 0xffff	# t0 &= 0x0000ffff;
	 sll	$t1, $t1, 16		# t1 <<= 16;

	and	$a4, $a4, $s4		# lo &= 0xaaaaaaaa;
	 and	$a5, $a5, $s4		# hi &= 0xaaaaaaaa;
	sll	$at, $a4, 1
	 sll	$t2, $a5, 1
	or	$a4, $a4, $at		# lo |= lo << 1;
	 or	$a5, $a5, $t2		# hi |= hi << 1;
	and	$a4, $a4, $s5		# lo &= 0xcccccccc;
	 and	$a5, $a5, $s5		# hi &= 0xcccccccc;
	sll	$at, $a4, 2
	 sll	$t2, $a5, 2
	or	$a4, $a4, $at		# lo |= lo << 2;
	 or	$a5, $a5, $t2		# hi |= hi << 2;
	and	$a4, $a4, $s6		# lo &= 0xf0f0f0f0;
	 and	$a5, $a5, $s6		# hi &= 0xf0f0f0f0;
	sll	$at, $a4, 4
	 sll	$t2, $a5, 4
	or	$a4, $a4, $at		# lo |= lo << 4;
	 or	$a5, $a5, $t2		# hi |= hi << 4;
	and	$a4, $a4, $s7		# lo &= 0xff00ff00;
	 and	$a5, $a5, $s7		# hi &= 0xff00ff00;
	sll	$at, $a4, 8
	 sll	$t2, $a5, 8
	or	$a4, $a4, $at		# lo |= lo << 8;
	 or	$a5, $a5, $t2		# hi |= hi << 8;
	srl	$a4, $a4, 16		# lo >>= 16;
	 and	$a5, $a5, $s8		# hi &= 0xffff0000;

	xor	$s10, $s10, $t0		# absorb
	xor	$s11, $s11, $a4
	xor	$s10, $s10, $t1
	xor	$s11, $s11, $a5

	sw	$s10, 0($A_flat)
	subu	$bsz, $bsz, 8
	sw	$s11, 4($A_flat)
	addu	$A_flat, $A_flat, 8
	bnez	$bsz, .Loop_block

	bal	__KeccakF1600

	lw	$bsz, 4*2($sp)
	lw	$len, 4*1($sp)
	lw	$inp, 4*0($sp)

	sltu	$at, $len, $bsz
	beqz	$at, .Loop_absorb

	lw	$s0, $A[0][1]+0($a0)
	lw	$s1, $A[0][1]+4($a0)
	lw	$s2, $A[0][2]+0($a0)
	lw	$s3, $A[0][2]+4($a0)
	lw	$s4, $A[1][3]+0($a0)
	lw	$s5, $A[1][3]+4($a0)
	not	$s0, $s0
	lw	$s6, $A[2][2]+0($a0)
	not	$s1, $s1
	lw	$s7, $A[2][2]+4($a0)
	not	$s2, $s2
	lw	$a4, $A[3][2]+0($a0)
	not	$s3, $s3
	lw	$a5, $A[3][2]+4($a0)
	not	$s4, $s4
	lw	$a6, $A[4][0]+0($a0)
	not	$s5, $s5
	lw	$a7, $A[4][0]+4($a0)
	sw	$s0, $A[0][1]+0($a0)
	not	$s6, $s6
	sw	$s1, $A[0][1]+4($a0)
	not	$s7, $s7
	sw	$s2, $A[0][2]+0($a0)
	not	$a4, $a4
	sw	$s3, $A[0][2]+4($a0)
	not	$a5, $a5
	sw	$s4, $A[1][3]+0($a0)
	not	$a6, $a6
	sw	$s5, $A[1][3]+4($a0)
	not	$a7, $a7
	sw	$s6, $A[2][2]+0($a0)
	sw	$s7, $A[2][2]+4($a0)
	sw	$a4, $A[3][2]+0($a0)
	sw	$a5, $A[3][2]+4($a0)
	sw	$a6, $A[4][0]+0($a0)
	sw	$a7, $A[4][0]+4($a0)

	lw	$ra,  4*19($sp)
	lw	$fp,  4*18($sp)
	lw	$s11, 4*17($sp)
	lw	$s10, 4*16($sp)
	lw	$s9,  4*15($sp)
	lw	$s8,  4*14($sp)
	lw	$s7,  4*13($sp)
	lw	$s6,  4*12($sp)
	lw	$s5,  4*11($sp)
	lw	$s4,  4*10($sp)
___
$code.<<___	if ($flavour =~ /nubi/);
	lw	$s3,  4*9($sp)
	lw	$s2,  4*8($sp)
	lw	$s1,  4*7($sp)
	lw	$s0,  4*6($sp)
	lw	$gp,  4*5($sp)
___
$code.=<<___;
.Labsorb_abort:
	move	$a0, $len		# return value
	move	$t0, $len
	addu	$sp,  $sp, 4*20
	jr	$ra
.end	SHA3_absorb
___
}
{
my ($A_flat, $out, $len, $bsz) = ($ra, $a1, $a2, $a3);
$code.=<<___;
.globl	SHA3_squeeze
.align	5
.ent	SHA3_squeeze
SHA3_squeeze:
	.frame	$sp, 4*20, $ra
	.mask	0xc0ff0000, -4
	.set	noreorder
	.cpload	$pf
	subu	$sp,  $sp, 4*16
	sw	$ra,  4*15($sp)
	sw	$fp,  4*14($sp)
	sw	$s11, 4*13($sp)
	sw	$s10, 4*12($sp)
	sw	$s9,  4*11($sp)
	sw	$s8,  4*10($sp)
	sw	$s7,  4*9($sp)
	sw	$s6,  4*8($sp)
	sw	$s5,  4*7($sp)
	sw	$s4,  4*6($sp)
	.set	reorder
	la	$fp, iotas

	sw	$bsz, 4*2($sp)
	move	$A_flat, $a0

	lui	$s4, 0x5555
	lui	$s5, 0x3333
	lui	$s6, 0x0f0f
	lui	$s7, 0x00ff
	ori	$s4, 0x5555		# 0x55555555
	ori	$s5, 0x3333		# 0x33333333
	ori	$s6, 0x0f0f		# 0x0f0f0f0f
	ori	$s7, 0x00ff		# 0x00ff00ff
	sll	$s8, $s4, 1		# 0xaaaaaaaa
	sll	$s9, $s5, 2		# 0xcccccccc
	sll	$s10, $s6, 4		# 0xf0f0f0f0
	sll	$s11, $s7, 8		# 0xff00ff00

.Loop_squeeze:
	lw	$a4, 0($A_flat)
	lw	$a5, 4($A_flat)
	addu	$A_flat, $A_flat, 8
	lui	$a7, 0xffff		# 0xffff0000

	andi	$t0, $a4, 0xffff	# t0 = lo & 0x0000ffff;
	 sll	$t1, $a5, 16		# t1 = hi << 16;
	sll	$at, $t0, 8
	 srl	$t2, $t1, 8
	or	$t0, $t0, $at		# t0 |= t0 << 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 1;
	and	$t0, $t0, $s7		# t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s11		# t1 &= 0xff00ff00;
	sll	$at, $t0, 4
	 srl	$t2, $t1, 4
	or	$t0, $t0, $at		# t0 |= t0 << 4;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 2;
	and	$t0, $t0, $s6		# t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s10		# t1 &= 0xf0f0f0f0;
	sll	$at, $t0, 2
	 srl	$t2, $t1, 2
	or	$t0, $t0, $at		# t0 |= t0 << 2;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 4;
	and	$t0, $t0, $s5		# t0 &= 0x33333333;
	 and	$t1, $t1, $s9		# t1 &= 0xcccccccc;
	sll	$at, $t0, 1
	 srl	$t2, $t1, 1
	or	$t0, $t0, $at		# t0 |= t0 >> 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 8;
	and	$t0, $t0, $s4		# t0 &= 0x55555555;
	 and	$t1, $t1, $s8		# t1 &= 0xaaaaaaaa;

	srl	$a4, $a4, 16		# lo >>= 16;
	 and	$a5, $a5, $a7		# hi &= 0xffff0000;
	sll	$at, $a4, 8
	 srl	$t2, $a5, 8
	or	$a4, $a4, $at		# lo |= lo << 8;
	 or	$a5, $a5, $t2		# hi |= hi >> 8;
	and	$a4, $a4, $s7		# lo &= 0x00ff00ff;
	 and	$a5, $a5, $s11		# hi &= 0xff00ff00;
	sll	$at, $a4, 4
	 srl	$t2, $a5, 4
	or	$a4, $a4, $at		# lo |= lo << 4;
	 or	$a5, $a5, $t2		# hi |= hi >> 4;
	and	$a4, $a4, $s6		# lo &= 0x0f0f0f0f;
	 and	$a5, $a5, $s10		# hi &= 0xf0f0f0f0;
	sll	$at, $a4, 2
	 srl	$t2, $a5, 2
	or	$a4, $a4, $at		# lo |= lo << 2;
	 or	$a5, $a5, $t2		# hi |= hi >> 2;
	and	$a4, $a4, $s5		# lo &= 0x33333333;
	 and	$a5, $a5, $s9		# hi &= 0xcccccccc;
	sll	$at, $a4, 1
	 srl	$t2, $a5, 1
	or	$a4, $a4, $at		# lo |= lo << 1;
	 or	$a5, $a5, $t2		# hi |= hi >> 1;
	and	$a4, $a4, $s4		# lo &= 0x55555555;
	 and	$a5, $a5, $s8		# hi &= 0xaaaaaaaa;

	sltu	$at, $len, 4
	or	$a5, $a5, $a4
	or	$a4, $t0, $t1
	bnez	$at, .Lsqueeze_tail

	srl	$a6, $a4, 8
	sb	$a4, 0($out)
	srl	$a7, $a4, 16
	sb	$a6, 1($out)
	srl	$t0, $a4, 24
	sb	$a7, 2($out)
	subu	$len, $len, 4
	sb	$t0, 3($out)
	sltu	$at, $len, 4
	addu	$out, $out, 4
	move	$a4, $a5
	bnez	$at, .Lsqueeze_tail

	srl	$a6, $a4, 8
	sb	$a4, 0($out)
	srl	$a7, $a4, 16
	sb	$a6, 1($out)
	srl	$t0, $a4, 24
	sb	$a7, 2($out)
	subu	$len, $len, 4
	sb	$t0, 3($out)
	addu	$out, $out, 4
	beqz	$len, .Lsqueeze_done

	subu	$bsz, $bsz, 8
	bnez	$bsz, .Loop_squeeze

	sw	$len, 4*1($sp)
	sw	$out, 4*0($sp)

	bal	KeccakF1600

	lw	$out, 4*0($sp)
	lw	$len, 4*1($sp)
	lw	$bsz, 4*2($sp)
	move	$A_flat, $a0
	b	.Loop_squeeze

.set	noreorder
.align	4
.Lsqueeze_tail:
	beqz	$len, .Lsqueeze_done
	subu	$len, $len, 1
	sb	$a4, 0($out)
	addu	$out, $out, 1
	b	.Lsqueeze_tail
	srl	$a4, $a4, 8

.Lsqueeze_done:
	lw	$ra,  4*15($sp)
	lw	$fp,  4*14($sp)
	lw	$s11, 4*13($sp)
	lw	$s10, 4*12($sp)
	lw	$s9,  4*11($sp)
	lw	$s8,  4*10($sp)
	lw	$s7,  4*9($sp)
	lw	$s6,  4*8($sp)
	lw	$s5,  4*7($sp)
	lw	$s4,  4*6($sp)
	jr	$ra
	addu	$sp,  $sp, 4*16
.end	SHA3_squeeze
___
}
$code.=<<___;
.rdata
.align 8	# strategic alignment and padding that allows to use
		# address value as loop termination condition...
	.word	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
iotas:
	.word	0x00000001, 0x00000000
	.word	0x00000000, 0x00000089
	.word	0x00000000, 0x8000008b
	.word	0x00000000, 0x80008080
	.word	0x00000001, 0x0000008b
	.word	0x00000001, 0x00008000
	.word	0x00000001, 0x80008088
	.word	0x00000001, 0x80000082
	.word	0x00000000, 0x0000000b
	.word	0x00000000, 0x0000000a
	.word	0x00000001, 0x00008082
	.word	0x00000000, 0x00008003
	.word	0x00000001, 0x0000808b
	.word	0x00000001, 0x8000000b
	.word	0x00000001, 0x8000008a
	.word	0x00000001, 0x80000081
	.word	0x00000000, 0x80000081
	.word	0x00000000, 0x80000008
	.word	0x00000000, 0x00000083
	.word	0x00000000, 0x80008003
	.word	0x00000001, 0x80008088
	.word	0x00000000, 0x80000088
	.word	0x00000001, 0x00008000
	.word	0x00000000, 0x80008082
.asciiz "Keccak-1600 absorb and squeeze for MIPS, CRYPTOGAMS by \@dot-asm"
___
}}}

print $code;
close STDOUT;
