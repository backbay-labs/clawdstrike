#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Keccak-1600 for RISC-V.
#
# March 2019
#
# This is transliteration of MIPS module [without big-endian option].
# See keccak1600-mips.pl for details...
#
# 24 cycles per byte processed with SHA3-256 on U74, ~50% faster than
# compiler-generated code, extra 33%, 18 cbp on JH7110, U74 with zbb.
# 19.4 cpb on C910.
#
# June 2024.
#
# Add CHERI support.
#
######################################################################
($zero,$ra,$sp,$gp,$tp) = map("x$_",(0..4));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7, 28..31));
######################################################################

$flavour = shift || "64";	# cheri64 or cheri are acceptable too

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
if ($flavour =~ /64/i) {{{
# registers
my @A = map([ "x$_", "x".($_+1), "x".($_+2), "x".($_+3), "x".($_+4) ],
            (7, 12, 17, 22, 27));
{
my @T = ($t0,$t1, $A[4][0],$A[4][1]);
my @D = ($A[0][4],$A[0][0],$A[0][1],$A[0][2],$A[0][3]);

# offsets into stack frame
my @E = map(8*$_, (0..4));
my @F = map(8*$_, (5..9));
my $_ra = 8*10;

$code.=<<___;
#if __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif

.text
.option	pic

.type	__KeccakF1600, \@function
__KeccakF1600:
	caddi	$sp, $sp, -8*12
	PUSH	$ra, $_ra($sp)

	sd	$A[4][0], $F[0]($sp)
	sd	$A[4][1], $F[1]($sp)
	cllc	$ra, iotas			# iotas

.Loop:
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

#ifdef	__riscv_zbb
	ror	$D[1], $D[3], 63
	xor	$D[1], $D[1], $T[0]		# D[1] = T[0] ^ ROL64(D[3], 1);
	ror	$D[2], $D[0], 63
	xor	$D[3], $D[3], $D[2]		# D[3] ^= ROL64(D[0], 1);
	ror	$D[2], $T[1], 63
	xor	$D[0], $D[0], $D[2]		# D[0] ^= ROL64(T[1], 1);
	ror	$D[2], $D[4], 63
	xor	$D[2], $D[2], $T[1]		# D[2] = T[1] ^ ROL64(D[4], 1)
	ror	$T[1], $T[0], 63
	xor	$D[4], $D[4], $T[1] 		# D[4] ^= ROL64(T[0], 1);
	xor	$T[0], $A[1][1], $D[1]

	ror	$T[1], $T[0], 64-$rhotates[1][1]

	xor	$T[0], $A[2][2], $D[2]
	 sd	$T[1], $F[1]($sp)		# offload new A[0][*]
	ror	$T[1], $T[0], 64-$rhotates[2][2]

	xor	$T[0], $A[3][3], $D[3]
	 sd	$T[1], $F[2]($sp)
	ror	$T[1], $T[0], 64-$rhotates[3][3]

	xor	$T[0], $A[4][4], $D[4]
	 sd	$T[1], $F[3]($sp)
	ror	$T[1], $T[0], 64-$rhotates[4][4]

	xor	$A[1][1], $A[1][4], $D[4]
	 sd	$T[1], $F[4]($sp)
	 xor	$A[2][2], $A[2][3], $D[3]
	  xor	$A[3][3], $A[3][2], $D[2]
	   xor	$A[4][4], $A[4][1], $D[1]
	ror	$A[1][1], $A[1][1], 64-$rhotates[1][4]
	 ror	$A[2][2], $A[2][2], 64-$rhotates[2][3]
	  ror	$A[3][3], $A[3][3], 64-$rhotates[3][2]
	   ror	$A[4][4], $A[4][4], 64-$rhotates[4][1]

	xor	$A[1][4], $A[4][2], $D[2]
	 xor	$A[2][3], $A[3][4], $D[4]
	  xor	$A[3][2], $A[2][1], $D[1]
	   xor	$A[4][1], $A[1][3], $D[3]
	ror	$A[1][4], $A[1][4], 64-$rhotates[4][2]
	 ror	$A[2][3], $A[2][3], 64-$rhotates[3][4]
	  ror	$A[3][2], $A[3][2], 64-$rhotates[2][1]
	   ror	$A[4][1], $A[4][1], 64-$rhotates[1][3]

	xor	$A[4][2], $A[2][4], $D[4]
	 xor	$A[3][4], $A[4][3], $D[3]
	  xor	$A[2][1], $A[1][2], $D[2]
	   xor	$A[1][3], $A[3][1], $D[1]
	ror	$A[4][2], $A[4][2], 64-$rhotates[2][4]
	 ror	$A[3][4], $A[3][4], 64-$rhotates[4][3]
	  ror	$A[2][1], $A[2][1], 64-$rhotates[1][2]
	   ror	$A[1][3], $A[1][3], 64-$rhotates[3][1]

	xor	$A[2][4], $A[4][0], $D[0]
	ld	$A[4][0], $E[2]($sp)		# load original A[0][*]
	 xor	$A[4][3], $A[3][0], $D[0]
	ld	$A[3][0], $E[4]($sp)
	  xor	$A[1][2], $A[2][0], $D[0]
	ld	$A[2][0], $E[1]($sp)
	   xor	$A[3][1], $A[1][0], $D[0]
	ld	$A[1][0], $E[3]($sp)
	ror	$A[2][4], $A[2][4], 64-$rhotates[4][0]
	 ror	$A[4][3], $A[4][3], 64-$rhotates[3][0]
	  ror	$A[1][2], $A[1][2], 64-$rhotates[2][0]
	   ror	$A[3][1], $A[3][1], 64-$rhotates[1][0]

	xor	$A[4][0], $A[4][0], $D[2]
	 xor	$A[3][0], $A[3][0], $D[4]
	  xor	$A[2][0], $A[2][0], $D[1]
	   xor	$A[1][0], $A[1][0], $D[3]
	ror	$A[4][0], $A[4][0], 64-$rhotates[0][2]
	 ror	$A[3][0], $A[3][0], 64-$rhotates[0][4]
	  ror	$A[2][0], $A[2][0], 64-$rhotates[0][1]
	   ror	$A[1][0], $A[1][0], 64-$rhotates[0][3]

	andn	$T[0], $A[1][2], $A[1][1]
	andn	$D[1], $A[1][3], $A[1][2]
	andn	$D[2], $A[1][4], $A[1][3]
	andn	$D[3], $A[1][0], $A[1][4]
	andn	$D[4], $A[1][1], $A[1][0]
	xor	$A[1][0], $A[1][0], $T[0]
	xor	$A[1][1], $A[1][1], $D[1]
	xor	$A[1][2], $A[1][2], $D[2]
	xor	$A[1][3], $A[1][3], $D[3]
	xor	$A[1][4], $A[1][4], $D[4]

	andn	$T[0], $A[2][2], $A[2][1]
	andn	$D[1], $A[2][3], $A[2][2]
	andn	$D[2], $A[2][4], $A[2][3]
	andn	$D[3], $A[2][0], $A[2][4]
	andn	$D[4], $A[2][1], $A[2][0]
	xor	$A[2][0], $A[2][0], $T[0]
	xor	$A[2][1], $A[2][1], $D[1]
	xor	$A[2][2], $A[2][2], $D[2]
	xor	$A[2][3], $A[2][3], $D[3]
	xor	$A[2][4], $A[2][4], $D[4]

	andn	$T[0], $A[3][2], $A[3][1]
	andn	$D[1], $A[3][3], $A[3][2]
	andn	$D[2], $A[3][4], $A[3][3]
	andn	$D[3], $A[3][0], $A[3][4]
	andn	$D[4], $A[3][1], $A[3][0]
	xor	$A[3][0], $A[3][0], $T[0]
	xor	$A[3][1], $A[3][1], $D[1]
	xor	$A[3][2], $A[3][2], $D[2]
	xor	$A[3][3], $A[3][3], $D[3]
	xor	$A[3][4], $A[3][4], $D[4]

	andn	$T[0], $A[4][2], $A[4][1]
	andn	$D[1], $A[4][3], $A[4][2]
	andn	$D[2], $A[4][4], $A[4][3]
	andn	$D[3], $A[4][0], $A[4][4]
	andn	$D[4], $A[4][1], $A[4][0]
	xor	$A[4][0], $A[4][0], $T[0]
	xor	$A[4][1], $A[4][1], $D[1]
	 ld	$A[0][0], $E[0]($sp)		# reload A[0][*]
	xor	$A[4][2], $A[4][2], $D[2]
	 ld	$A[0][1], $F[1]($sp)
	xor	$A[4][3], $A[4][3], $D[3]
	 ld	$A[0][2], $F[2]($sp)
	xor	$A[4][4], $A[4][4], $D[4]
	 ld	$A[0][3], $F[3]($sp)

	xor	$A[0][0], $A[0][0], $D[0]
	 ld	$A[0][4], $F[4]($sp)

	 sd	$A[4][0], $F[0]($sp)		# make room for T[2]
	andn	$T[2], $A[0][4], $A[0][3]
	 sd	$A[4][1], $F[1]($sp)		# make room for T[3]
	andn	$T[3], $A[0][0], $A[0][4]
	andn	$T[0], $A[0][3], $A[0][2]
	andn	$T[1], $A[0][2], $A[0][1]
	xor	$A[0][2], $A[0][2], $T[2]
	andn	$T[2], $A[0][1], $A[0][0]
	xor	$A[0][3], $A[0][3], $T[3]
	 ld	$T[3], 0($ra)			# *iotas++
	 caddi	$ra, $ra, 8
	xor	$A[0][1], $A[0][1], $T[0]
	xor	$A[0][0], $A[0][0], $T[1]
	xor	$A[0][4], $A[0][4], $T[2]
#else
	add	$D[1], $D[3], $D[3]		# dsll $D[3], 1
	xor	$D[1], $D[1], $T[0]
	srl	$D[2], $D[3], 63
	xor	$D[1], $D[1], $D[2]		# D[1] = T[0] ^ ROL64(D[3], 1);
	add	$D[2], $D[0], $D[0]		# dsll $D[0], 1
	xor	$D[3], $D[3], $D[2]
	srl	$D[2], $D[0], 63
	xor	$D[3], $D[3], $D[2]		# D[3] ^= ROL64(D[0], 1);
	add	$D[2], $T[1], $T[1]		# dsll $T[1], 1
	xor	$D[0], $D[0], $D[2]
	srl	$D[2], $T[1], 63
	xor	$D[0], $D[0], $D[2]		# D[0] ^= ROL64(T[1], 1);
	add	$D[2], $D[4], $D[4]		# dsll $D[4], 1
	xor	$D[2], $D[2], $T[1]
	srl	$T[1], $D[4], 63
	xor	$D[2], $D[2], $T[1]		# D[2] = T[1] ^ ROL64(D[4], 1);
	add	$T[1], $T[0], $T[0]		# dsll $T[0], 1
	xor	$D[4], $D[4], $T[1]
	srl	$T[1], $T[0], 63
	xor	$D[4], $D[4], $T[1]		# D[4] ^= ROL64(T[0], 1);


	xor	$T[0], $A[1][1], $D[1]
	sll	$T[1], $T[0], $rhotates[1][1]
	srl	$T[0], $T[0], 64-$rhotates[1][1]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[2][2], $D[2]
	 sd	$T[1], $F[1]($sp)		# offload new A[0][*]
	sll	$T[1], $T[0], $rhotates[2][2]
	srl	$T[0], $T[0], 64-$rhotates[2][2]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[3][3], $D[3]
	 sd	$T[1], $F[2]($sp)
	sll	$T[1], $T[0], $rhotates[3][3]
	srl	$T[0], $T[0], 64-$rhotates[3][3]
	or	$T[1], $T[1], $T[0]

	xor	$T[0], $A[4][4], $D[4]
	 sd	$T[1], $F[3]($sp)
	sll	$T[1], $T[0], $rhotates[4][4]
	srl	$T[0], $T[0], 64-$rhotates[4][4]
	or	$T[1], $T[1], $T[0]


	xor	$A[1][1], $A[1][4], $D[4]
	 xor	$A[2][2], $A[2][3], $D[3]
	  sd	$T[1], $F[4]($sp)
	srl	$T[0], $A[1][1], 64-$rhotates[1][4]
	 srl	$T[1], $A[2][2], 64-$rhotates[2][3]
	sll	$A[1][1], $A[1][1], $rhotates[1][4]
	 sll	$A[2][2], $A[2][2], $rhotates[2][3]

	xor	$A[3][3], $A[3][2], $D[2]
	 xor	$A[4][4], $A[4][1], $D[1]
	  or	$A[1][1], $A[1][1], $T[0]
	srl	$T[0], $A[3][3], 64-$rhotates[3][2]
	   or	$A[2][2], $A[2][2], $T[1]
	 srl	$T[1], $A[4][4], 64-$rhotates[4][1]
	sll	$A[3][3], $A[3][3], $rhotates[3][2]
	 sll	$A[4][4], $A[4][4], $rhotates[4][1]


	xor	$A[1][4], $A[4][2], $D[2]
	 xor	$A[2][3], $A[3][4], $D[4]
	  or	$A[3][3], $A[3][3], $T[0]
	srl	$T[0], $A[1][4], 64-$rhotates[4][2]
	   or	$A[4][4], $A[4][4], $T[1]
	 srl	$T[1], $A[2][3], 64-$rhotates[3][4]
	sll	$A[1][4], $A[1][4], $rhotates[4][2]
	 sll	$A[2][3], $A[2][3], $rhotates[3][4]

	xor	$A[3][2], $A[2][1], $D[1]
	 xor	$A[4][1], $A[1][3], $D[3]
	  or	$A[1][4], $A[1][4], $T[0]
	srl	$T[0], $A[3][2], 64-$rhotates[2][1]
	   or	$A[2][3], $A[2][3], $T[1]
	 srl	$T[1], $A[4][1], 64-$rhotates[1][3]
	sll	$A[3][2], $A[3][2], $rhotates[2][1]
	 sll	$A[4][1], $A[4][1], $rhotates[1][3]


	xor	$A[4][2], $A[2][4], $D[4]
	 xor	$A[3][4], $A[4][3], $D[3]
	  or	$A[3][2], $A[3][2], $T[0]
	srl	$T[0], $A[4][2], 64-$rhotates[2][4]
	   or	$A[4][1], $A[4][1], $T[1]
	 srl	$T[1], $A[3][4], 64-$rhotates[4][3]
	sll	$A[4][2], $A[4][2], $rhotates[2][4]
	 sll	$A[3][4], $A[3][4], $rhotates[4][3]

	xor	$A[2][1], $A[1][2], $D[2]
	 xor	$A[1][3], $A[3][1], $D[1]
	  or	$A[4][2], $A[4][2], $T[0]
	srl	$T[0], $A[2][1], 64-$rhotates[1][2]
	   or	$A[3][4], $A[3][4], $T[1]
	 srl	$T[1], $A[1][3], 64-$rhotates[3][1]
	sll	$A[2][1], $A[2][1], $rhotates[1][2]
	 sll	$A[1][3], $A[1][3], $rhotates[3][1]


	xor	$A[2][4], $A[4][0], $D[0]
	  ld	$A[4][0], $E[2]($sp)		# load original A[0][*]
	 xor	$A[4][3], $A[3][0], $D[0]
	  ld	$A[3][0], $E[4]($sp)
	  or	$A[2][1], $A[2][1], $T[0]
	srl	$T[0], $A[2][4], 64-$rhotates[4][0]
	   or	$A[1][3], $A[1][3], $T[1]
	 srl	$T[1], $A[4][3], 64-$rhotates[3][0]
	sll	$A[2][4], $A[2][4], $rhotates[4][0]
	 sll	$A[4][3], $A[4][3], $rhotates[3][0]

	xor	$A[1][2], $A[2][0], $D[0]
	  ld	$A[2][0], $E[1]($sp)
	 xor	$A[3][1], $A[1][0], $D[0]
	  ld	$A[1][0], $E[3]($sp)
	  or	$A[2][4], $A[2][4], $T[0]
	srl	$T[0], $A[1][2], 64-$rhotates[2][0]
	   or	$A[4][3], $A[4][3], $T[1]
	 srl	$T[1], $A[3][1], 64-$rhotates[1][0]
	sll	$A[1][2], $A[1][2], $rhotates[2][0]
	 sll	$A[3][1], $A[3][1], $rhotates[1][0]


	xor	$A[4][0], $A[4][0], $D[2]
	 xor	$A[3][0], $A[3][0], $D[4]
	  or	$A[1][2], $A[1][2], $T[0]
	srl	$T[0], $A[4][0], 64-$rhotates[0][2]
	   or	$A[3][1], $A[3][1], $T[1]
	 srl	$T[1], $A[3][0], 64-$rhotates[0][4]
	sll	$A[4][0], $A[4][0], $rhotates[0][2]
	 sll	$A[3][0], $A[3][0], $rhotates[0][4]

	xor	$A[2][0], $A[2][0], $D[1]
	 xor	$A[1][0], $A[1][0], $D[3]
	  or	$A[4][0], $A[4][0], $T[0]
	srl	$T[0], $A[2][0], 64-$rhotates[0][1]
	   or	$A[3][0], $A[3][0], $T[1]
	 srl	$T[1], $A[1][0], 64-$rhotates[0][3]
	sll	$A[2][0], $A[2][0], $rhotates[0][1]
	 sll	$A[1][0], $A[1][0], $rhotates[0][3]
	or	$A[2][0], $A[2][0], $T[0]
	 or	$A[1][0], $A[1][0], $T[1]

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
	 ld	$T[3], 0($ra)			# *iotas++
	 caddi	$ra, $ra, 8
	xor	$A[0][4], $A[0][4], $T[2]
	xor	$A[0][0], $A[0][0], $T[0]
	xor	$A[0][1], $A[0][1], $T[1]
#endif
	xor	$A[0][0], $A[0][0], $T[3]	# A[0][0] ^= iotas[i]

	andi	$T[0], $ra, 0xff
	bnez	$T[0], .Loop

	POP	$ra, $_ra($sp)

	ld	$A[4][0], $F[0]($sp)
	ld	$A[4][1], $F[1]($sp)

	caddi	$sp, $sp, 8*12
	ret
.size	__KeccakF1600, .-__KeccakF1600

.type	KeccakF1600, \@function
KeccakF1600:
	caddi	$sp, $sp, -__SIZEOF_POINTER__*16

	PUSH	$ra,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*8($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*7($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*6($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*5($sp)
	PUSH	$s10, __SIZEOF_POINTER__*4($sp)
	PUSH	$s11, __SIZEOF_POINTER__*3($sp)

	PUSH	$a0, 0($sp)
	cmove	$ra, $a0

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

#ifndef	__riscv_zbb
	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]
#endif

	jal	__KeccakF1600

	POP	$t1, 0($sp)

#ifndef	__riscv_zbb
	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]
#endif

	sd	$A[0][0], 0x00($t1)
	sd	$A[0][1], 0x08($t1)
	sd	$A[0][2], 0x10($t1)
	sd	$A[0][3], 0x18($t1)
	sd	$A[0][4], 0x20($t1)
	sd	$A[1][0], 0x28($t1)
	sd	$A[1][1], 0x30($t1)
	sd	$A[1][2], 0x38($t1)
	sd	$A[1][3], 0x40($t1)
	sd	$A[1][4], 0x48($t1)
	sd	$A[2][0], 0x50($t1)
	sd	$A[2][1], 0x58($t1)
	sd	$A[2][2], 0x60($t1)
	sd	$A[2][3], 0x68($t1)
	sd	$A[2][4], 0x70($t1)
	sd	$A[3][0], 0x78($t1)
	sd	$A[3][1], 0x80($t1)
	sd	$A[3][2], 0x88($t1)
	sd	$A[3][3], 0x90($t1)
	sd	$A[3][4], 0x98($t1)
	sd	$A[4][0], 0xa0($t1)
	sd	$A[4][1], 0xa8($t1)
	sd	$A[4][2], 0xb0($t1)
	sd	$A[4][3], 0xb8($t1)
	sd	$A[4][4], 0xc0($t1)

	POP	$ra,  __SIZEOF_POINTER__*15($sp)
	POP	$s0,  __SIZEOF_POINTER__*14($sp)
	POP	$s1,  __SIZEOF_POINTER__*13($sp)
	POP	$s2,  __SIZEOF_POINTER__*12($sp)
	POP	$s3,  __SIZEOF_POINTER__*11($sp)
	POP	$s4,  __SIZEOF_POINTER__*10($sp)
	POP	$s5,  __SIZEOF_POINTER__*9($sp)
	POP	$s6,  __SIZEOF_POINTER__*8($sp)
	POP	$s7,  __SIZEOF_POINTER__*7($sp)
	POP	$s8,  __SIZEOF_POINTER__*6($sp)
	POP	$s9,  __SIZEOF_POINTER__*5($sp)
	POP	$s10, __SIZEOF_POINTER__*4($sp)
	POP	$s11, __SIZEOF_POINTER__*3($sp)
	caddi	$sp, $sp, __SIZEOF_POINTER__*16
	ret
.size	KeccakF1600, .-KeccakF1600
___
}
{
my ($inp,$len,$bsz) = ($A[4][2],$A[4][3],$A[4][4]);
my @T = ($A[4][1],$len,$ra);

$code.=<<___;
.type	__load_n_xor, \@function
__load_n_xor:
	lbu	$T[0], 0($inp)
	lbu	$T[1], 1($inp)
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 2($inp)
	sll	$T[1], $T[1], 8
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 3($inp)
	sll	$T[0], $T[0], 16
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 4($inp)
	sll	$T[1], $T[1], 24
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 5($inp)
	sll	$T[0], $T[0], 32
	xor	$A[4][0], $A[4][0], $T[0]
	lbu	$T[0], 6($inp)
	sll	$T[1], $T[1], 40
	xor	$A[4][0], $A[4][0], $T[1]
	lbu	$T[1], 7($inp)
	sll	$T[0], $T[0], 48
	xor	$A[4][0], $A[4][0], $T[0]
	sll	$T[1], $T[1], 56
	xor	$A[4][0], $A[4][0], $T[1]
	caddi	$inp, $inp, 8
	ret
.size	__load_n_xor, .-__load_n_xor

.globl	SHA3_absorb
.type	SHA3_absorb, \@function
SHA3_absorb:
	bltu	$a2, $a3, .Labsorb_abort

	caddi	$sp, $sp, -__SIZEOF_POINTER__*20

	PUSH	$ra,  __SIZEOF_POINTER__*19($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*18($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*17($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*16($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s10, __SIZEOF_POINTER__*8($sp)
	PUSH	$s11, __SIZEOF_POINTER__*7($sp)

	cmove	$t1,  $a0
	cmove	$inp, $a1
	PUSH	$a0,  __SIZEOF_POINTER__*0($sp)	# put aside A[][]
	mv	$len, $a2
	sd	$a3,  __SIZEOF_POINTER__*3($sp)	# put aside bsz
	mv	$bsz, $a3

	ld	$A[0][0], 0x00($a0)
	ld	$A[0][1], 0x08($a0)
	ld	$A[0][2], 0x10($a0)
	ld	$A[0][3], 0x18($a0)
	ld	$A[0][4], 0x20($t1)
	ld	$A[1][0], 0x28($t1)
	ld	$A[1][1], 0x30($t1)
	ld	$A[1][2], 0x38($t1)
	ld	$A[1][3], 0x40($t1)
	ld	$A[1][4], 0x48($t1)
	ld	$A[2][0], 0x50($t1)
	ld	$A[2][1], 0x58($t1)
	ld	$A[2][2], 0x60($t1)
	ld	$A[2][3], 0x68($t1)
	ld	$A[2][4], 0x70($t1)
	ld	$A[3][0], 0x78($t1)
	ld	$A[3][1], 0x80($t1)
	ld	$A[3][2], 0x88($t1)
	ld	$A[3][3], 0x90($t1)
	ld	$A[3][4], 0x98($t1)
	ld	$A[4][0], 0xa0($t1)

#ifndef	__riscv_zbb
	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]
#endif

.Loop_absorb:
	sub	$len, $len, $bsz
	cadd	$ra,  $inp, $bsz		# pointer to next block
	sd	$len, __SIZEOF_POINTER__*2($sp)
	PUSH	$ra,  __SIZEOF_POINTER__*1($sp)

	sd	$A[4][0], 0xa0($t1)		# borrow even A[4][0]

	mv	$A[4][0], $A[0][0]
	jal	__load_n_xor
	mv	$A[0][0],$A[4][0]
	mv	$A[4][0], $A[0][1]
	jal	__load_n_xor
	mv	$A[0][1],$A[4][0]
	mv	$A[4][0], $A[0][2]
	jal	__load_n_xor
	mv	$A[0][2],$A[4][0]
	mv	$A[4][0], $A[0][3]
	jal	__load_n_xor
	mv	$A[0][3],$A[4][0]
	mv	$A[4][0], $A[0][4]
	jal	__load_n_xor
	mv	$A[0][4],$A[4][0]
	mv	$A[4][0], $A[1][0]
	jal	__load_n_xor
	mv	$A[1][0],$A[4][0]
	mv	$A[4][0], $A[1][1]
	jal	__load_n_xor
	mv	$A[1][1],$A[4][0]
	mv	$A[4][0], $A[1][2]
	jal	__load_n_xor
	mv	$A[1][2],$A[4][0]
	mv	$A[4][0], $A[1][3]
	jal	__load_n_xor
	li	$T[0], 72
	mv	$A[1][3],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	mv	$A[4][0], $A[1][4]
	jal	__load_n_xor
	mv	$A[1][4],$A[4][0]
	mv	$A[4][0], $A[2][0]
	jal	__load_n_xor
	mv	$A[2][0],$A[4][0]
	mv	$A[4][0], $A[2][1]
	jal	__load_n_xor
	mv	$A[2][1],$A[4][0]
	mv	$A[4][0], $A[2][2]
	jal	__load_n_xor
	li	$T[0], 104
	mv	$A[2][2],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	mv	$A[4][0], $A[2][3]
	jal	__load_n_xor
	mv	$A[2][3],$A[4][0]
	mv	$A[4][0], $A[2][4]
	jal	__load_n_xor
	mv	$A[2][4],$A[4][0]
	mv	$A[4][0], $A[3][0]
	jal	__load_n_xor
	mv	$A[3][0],$A[4][0]
	mv	$A[4][0], $A[3][1]
	jal	__load_n_xor
	li	$T[0], 136
	mv	$A[3][1],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	mv	$A[4][0], $A[3][2]
	jal	__load_n_xor
	li	$T[0], 144
	mv	$A[3][2],$A[4][0]
	beq	$bsz, $T[0], .Lprocess_block2

	mv	$A[4][0], $A[3][3]
	jal	__load_n_xor
	mv	$A[3][3],$A[4][0]
	mv	$A[4][0], $A[3][4]
	jal	__load_n_xor
	mv	$A[3][4],$A[4][0]
	ld	$A[4][0], 0xa0($t1)
	jal	__load_n_xor
	j	.Lprocess_block

.Lprocess_block2:
	ld	$A[4][0], 0xa0($t1)

.Lprocess_block:
	ld	$A[4][1], 0xa8($t1)
	ld	$A[4][2], 0xb0($t1)
	ld	$A[4][3], 0xb8($t1)
	ld	$A[4][4], 0xc0($t1)

	jal	__KeccakF1600

	POP	$t1, __SIZEOF_POINTER__*0($sp)	# pull A[][]

	sd	$A[4][1], 0xa8($t1)
	sd	$A[4][2], 0xb0($t1)
	sd	$A[4][3], 0xb8($t1)
	sd	$A[4][4], 0xc0($t1)

	ld	$bsz, __SIZEOF_POINTER__*3($sp)
	ld	$len, __SIZEOF_POINTER__*2($sp)
	POP	$inp, __SIZEOF_POINTER__*1($sp)	# pointer to next block

	bgeu	$len, $bsz, .Loop_absorb	# len < bsz?

#ifndef	__riscv_zbb
	not	$A[0][1], $A[0][1]
	not	$A[0][2], $A[0][2]
	not	$A[1][3], $A[1][3]
	not	$A[2][2], $A[2][2]
	not	$A[3][2], $A[3][2]
	not	$A[4][0], $A[4][0]
#endif

	sd	$A[0][0], 0x00($t1)
	sd	$A[0][1], 0x08($t1)
	sd	$A[0][2], 0x10($t1)
	sd	$A[0][3], 0x18($t1)
	sd	$A[0][4], 0x20($t1)
	sd	$A[1][0], 0x28($t1)
	sd	$A[1][1], 0x30($t1)
	sd	$A[1][2], 0x38($t1)
	sd	$A[1][3], 0x40($t1)
	sd	$A[1][4], 0x48($t1)
	sd	$A[2][0], 0x50($t1)
	sd	$A[2][1], 0x58($t1)
	sd	$A[2][2], 0x60($t1)
	sd	$A[2][3], 0x68($t1)
	sd	$A[2][4], 0x70($t1)
	sd	$A[3][0], 0x78($t1)
	sd	$A[3][1], 0x80($t1)
	sd	$A[3][2], 0x88($t1)
	sd	$A[3][3], 0x90($t1)
	sd	$A[3][4], 0x98($t1)
	sd	$A[4][0], 0xa0($t1)

	mv	$a0, $len			# return value

	POP	$ra,  __SIZEOF_POINTER__*19($sp)
	POP	$s0,  __SIZEOF_POINTER__*18($sp)
	POP	$s1,  __SIZEOF_POINTER__*17($sp)
	POP	$s2,  __SIZEOF_POINTER__*16($sp)
	POP	$s3,  __SIZEOF_POINTER__*15($sp)
	POP	$s4,  __SIZEOF_POINTER__*14($sp)
	POP	$s5,  __SIZEOF_POINTER__*13($sp)
	POP	$s6,  __SIZEOF_POINTER__*12($sp)
	POP	$s7,  __SIZEOF_POINTER__*11($sp)
	POP	$s8,  __SIZEOF_POINTER__*10($sp)
	POP	$s9,  __SIZEOF_POINTER__*9($sp)
	POP	$s10, __SIZEOF_POINTER__*8($sp)
	POP	$s11, __SIZEOF_POINTER__*7($sp)
	caddi	$sp, $sp, __SIZEOF_POINTER__*20
	ret

.Labsorb_abort:
	mv	$a0, $a2			# return value
	ret
.size	SHA3_absorb, .-SHA3_absorb
___
}
{
my ($A_flat, $out, $len, $bsz) = ($s0, $s1, $s2, $s3);

$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze, \@function
SHA3_squeeze:
	caddi	$sp, $sp, -__SIZEOF_POINTER__*6

	PUSH	$ra, __SIZEOF_POINTER__*5($sp)
	PUSH	$s0, __SIZEOF_POINTER__*3($sp)
	PUSH	$s1, __SIZEOF_POINTER__*2($sp)
	PUSH	$s2, __SIZEOF_POINTER__*1($sp)
	PUSH	$s3, __SIZEOF_POINTER__*0($sp)

	cmove	$A_flat, $a0
	cmove	$out, $a1
	mv	$len, $a2
	mv	$bsz, $a3

.Loop_squeeze:
	ld	$a4, 0($a0)
	sltu	$ra, $len, 8			# len < 8?
	cadd	$a0, $a0, 8
	bnez	$ra, .Lsqueeze_tail

	srl	$a5, $a4, 8
	sb	$a4, 0($out)
	srl	$a6, $a4, 16
	sb	$a5, 1($out)
	srl	$a7, $a4, 24
	sb	$a6, 2($out)
	srl	$t0, $a4, 32
	sb	$a7, 3($out)
	srl	$a5, $a4, 40
	sb	$t0, 4($out)
	srl	$a6, $a4, 48
	sb	$a5, 5($out)
	srl	$a7, $a4, 56
	sb	$a6, 6($out)
	addi	$len, $len, -8			# len -= 8
	sb	$a7, 7($out)
	caddi	$out, $out, 8
	beqz	$len, .Lsqueeze_done

	addi	$a3, $a3, -8
	bnez	$a3, .Loop_squeeze

	cmove	$a0, $A_flat
	jal	KeccakF1600

	cmove	$a0, $A_flat
	mv	$a3, $bsz
	j	.Loop_squeeze

.Lsqueeze_tail:
	sb	$a4, 0($out)
	caddi	$out, $out, 1
	addi	$len, $len, -1
	srl	$a4, $a4, 8
	bnez	$len, .Lsqueeze_tail

.Lsqueeze_done:
	POP	$ra, __SIZEOF_POINTER__*5($sp)
	POP	$s0, __SIZEOF_POINTER__*3($sp)
	POP	$s1, __SIZEOF_POINTER__*2($sp)
	POP	$s2, __SIZEOF_POINTER__*1($sp)
	POP	$s3, __SIZEOF_POINTER__*0($sp)
	caddi	$sp, $sp, __SIZEOF_POINTER__*6
	ret
.size	SHA3_squeeze, .-SHA3_squeeze
___
}
$code.=<<___;
.section	.rodata
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
.string	"Keccak-1600 absorb and squeeze for RISC-V, CRYPTOGAMS by \@dot-asm"
___
}}} else {{{
######################################################################
# 32-bit code path
#

my @A = map([ 8*$_, 8*($_+1), 8*($_+2), 8*($_+3), 8*($_+4) ], (0,5,10,15,20));

my @C = map("x$_", (12..21));
my @D = map("x$_", (22..31));
my @T = map("x$_", (6..9));

$code.=<<___;
#if __riscv_xlen == 32
# if __SIZEOF_POINTER__ == 8
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sw
#  define POP	lw
# endif
# define srlw	srl
# define rorw	ror
#elif __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif

.text

.option	pic

.type	__KeccakF1600, \@function
__KeccakF1600:
	caddi	$sp, $sp, -224

	cmove	$a1, $sp
	cllc	$t0, iotas
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

#ifdef	__riscv_zbb
	rorw	@D[2], @C[5], 31
	xor	@D[3], @C[4], @C[1]
	xor	@D[2], @D[2], @C[0]	# D[1] = ROL64(C[2], 1) ^ C[0];

	rorw	@D[4], @C[7], 31
	xor	@D[5], @C[6], @C[3]
	xor	@D[4], @D[4], @C[2]	# D[2] = ROL64(C[3], 1) ^ C[1];

	rorw	@D[6], @C[9], 31
	xor	@D[7], @C[8], @C[5]
	xor	@D[6], @D[6], @C[4]	# D[3] = ROL64(C[4], 1) ^ C[2];

	rorw	@D[8], @C[1], 31
	xor	@D[9], @C[0], @C[7]
	xor	@D[8], @D[8], @C[6]	# D[4] = ROL64(C[0], 1) ^ C[3];

	rorw	@D[0], @C[3], 31
	xor	@D[1], @C[2], @C[9]
	xor	@D[0], @D[0], @C[8]	# D[0] = ROL64(C[1], 1) ^ C[4];
#else
	srlw	@T[0], @C[4], 31
	add	@T[1], @C[5], @C[5]
	srlw	@T[2], @C[5], 31
	add	@T[3], @C[4], @C[4]
	or	@D[3], @T[1], @T[0]
	or	@D[2], @T[3], @T[2]
	xor	@D[3], @D[3], @C[1]
	xor	@D[2], @D[2], @C[0]	# D[1] = ROL64(C[2], 1) ^ C[0];

	srlw	@T[0], @C[6], 31
	add	@T[1], @C[7], @C[7]
	srlw	@T[2], @C[7], 31
	add	@T[3], @C[6], @C[6]
	or	@D[5], @T[1], @T[0]
	or	@D[4], @T[3], @T[2]
	xor	@D[5], @D[5], @C[3]
	xor	@D[4], @D[4], @C[2]	# D[2] = ROL64(C[3], 1) ^ C[1];

	srlw	@T[0], @C[8], 31
	add	@T[1], @C[9], @C[9]
	srlw	@T[2], @C[9], 31
	add	@T[3], @C[8], @C[8]
	or	@D[7], @T[1], @T[0]
	or	@D[6], @T[3], @T[2]
	xor	@D[7], @D[7], @C[5]
	xor	@D[6], @D[6], @C[4]	# D[3] = ROL64(C[4], 1) ^ C[2];

	srlw	@T[0], @C[0], 31
	add	@T[1], @C[1], @C[1]
	srlw	@T[2], @C[1], 31
	add	@T[3], @C[0], @C[0]
	or	@D[9], @T[1], @T[0]
	or	@D[8], @T[3], @T[2]
	xor	@D[9], @D[9], @C[7]
	xor	@D[8], @D[8], @C[6]	# D[4] = ROL64(C[0], 1) ^ C[3];

	srlw	@T[0], @C[2], 31
	add	@T[1], @C[3], @C[3]
	srlw	@T[2], @C[3], 31
	add	@T[3], @C[2], @C[2]
	or	@D[1], @T[1], @T[0]
	or	@D[0], @T[3], @T[2]
	xor	@D[1], @D[1], @C[9]
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
	xor	@C[7], @C[7], @D[6]
	xor	@C[8], @C[8], @D[8]
	xor	@C[9], @C[9], @D[9]

#ifdef	__riscv_zbb
	rorw	@C[2], @C[2], 32-22
	 lw	@T[2], 0($t0)		# *iotas++
	rorw	@C[3], @C[3], 32-22
	 lw	@T[3], 4($t0)
	rorw	@C[4], @C[4], 31-21
	 cadd	$t0, $t0, 8
	rorw	@C[5], @C[5], 32-21
	rorw	@C[6], @C[6], 31-10
	rorw	@C[7], @C[7], 32-10
	rorw	@C[8], @C[8], 32-7
	rorw	@C[9], @C[9], 32-7
#else
	sllw	@T[0], @C[3], 12
	srlw	@T[1], @C[2], 32-12
	sllw	@T[2], @C[2], 12
	srlw	@T[3], @C[3], 32-12
	or	@C[2], @T[1], @T[0]
	or	@C[3], @T[3], @T[2]	# C[1] = ROL64(A[1][1], 44)

	sllw	@T[0], @C[4], 11
	srlw	@T[1], @C[5], 32-11
	sllw	@T[2], @C[5], 11
	srlw	@T[3], @C[4], 32-11
	or	@C[4], @T[1], @T[0]
	or	@C[5], @T[3], @T[2]	# C[2] = ROL64(A[2][2], 43)

	sllw	@T[0], @C[7], 21
	srlw	@T[1], @C[6], 32-21
	sllw	@T[2], @C[6], 21
	srlw	@T[3], @C[7], 32-21
	or	@C[6], @T[1], @T[0]
	or	@C[7], @T[3], @T[2]	# C[3] = ROL64(A[3][3], 21)

	sllw	@T[0], @C[8], 14
	srlw	@T[1], @C[9], 32-14
	sllw	@T[2], @C[9], 14
	srlw	@T[3], @C[8], 32-14
	or	@C[8], @T[1], @T[0]
	or	@C[9], @T[3], @T[2]	# C[4] = ROL64(A[4][4], 14)

	 lw	@T[2], 0($t0)		# *iotas++
	 lw	@T[3], 4($t0)
	 cadd	$t0, $t0, 8
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

#ifdef	__riscv_zbb
	rorw	@C[0], @C[0], 32-14
	rorw	@C[1], @C[1], 32-14
	rorw	@C[2], @C[2], 32-10
	rorw	@C[3], @C[3], 32-10
	rorw	@C[4], @C[4], 31-1
	rorw	@C[5], @C[5], 32-1
	rorw	@C[6], @C[6], 31-22
	rorw	@C[7], @C[7], 32-22
	rorw	@C[8], @C[8], 31-30
	rorw	@C[9], @C[9], 32-30
#else
	sllw	@T[0], @C[0], 28
	srlw	@T[1], @C[1], 32-28
	sllw	@T[2], @C[1], 28
	srlw	@T[3], @C[0], 32-28
	or	@C[0], @T[1], @T[0]
	or	@C[1], @T[3], @T[2]	# C[0] = ROL64(A[0][3], 28)

	sllw	@T[0], @C[2], 20
	srlw	@T[1], @C[3], 32-20
	sllw	@T[2], @C[3], 20
	srlw	@T[3], @C[2], 32-20
	or	@C[2], @T[1], @T[0]
	or	@C[3], @T[3], @T[2]	# C[1] = ROL64(A[1][4], 20)

	sllw	@T[0], @C[5], 3
	srlw	@T[1], @C[4], 32-3
	sllw	@T[2], @C[4], 3
	srlw	@T[3], @C[5], 32-3
	or	@C[4], @T[1], @T[0]
	or	@C[5], @T[3], @T[2]	# C[2] = ROL64(A[2][0], 3)

	sllw	@T[0], @C[6], 13
	srlw	@T[1], @C[7], 32-13
	sllw	@T[2], @C[7], 13
	srlw	@T[3], @C[6], 32-13
	or	@C[6], @T[1], @T[0]
	or	@C[7], @T[3], @T[2]	# C[3] = ROL64(A[3][1], 45)

	sllw	@T[0], @C[8], 29
	srlw	@T[1], @C[9], 32-29
	sllw	@T[2], @C[9], 29
	srlw	@T[3], @C[8], 32-29
	or	@C[8], @T[1], @T[0]
	or	@C[9], @T[3], @T[2]	# C[4] = ROL64(A[4][2], 61)
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

#ifdef	__riscv_zbb
	rorw	@C[0], @C[0], 31-0
	#rorw	@C[1], @C[1], 32-0
	rorw	@C[2], @C[2], 32-3
	rorw	@C[3], @C[3], 32-3
	rorw	@C[4], @C[4], 31-12
	rorw	@C[5], @C[5], 32-12
	rorw	@C[6], @C[6], 32-4
	rorw	@C[7], @C[7], 32-4
	rorw	@C[8], @C[8], 32-9
	rorw	@C[9], @C[9], 32-9
#else
	sllw	@T[0], @C[1], 1
	srlw	@T[1], @C[0], 32-1
	sllw	@T[2], @C[0], 1
	srlw	@T[3], @C[1], 32-1
	or	@C[0], @T[1], @T[0]
	or	@C[1], @T[3], @T[2]	# C[0] = ROL64(A[0][1], 1)

	sllw	@T[0], @C[2], 6
	srlw	@T[1], @C[3], 32-6
	sllw	@T[2], @C[3], 6
	srlw	@T[3], @C[2], 32-6
	or	@C[2], @T[1], @T[0]
	or	@C[3], @T[3], @T[2]	# C[1] = ROL64(A[1][2], 6)

	sllw	@T[0], @C[5], 25
	srlw	@T[1], @C[4], 32-25
	sllw	@T[2], @C[4], 25
	srlw	@T[3], @C[5], 32-25
	or	@C[4], @T[1], @T[0]
	or	@C[5], @T[3], @T[2]	# C[2] = ROL64(A[2][3], 25)

	sllw	@T[0], @C[6], 8
	srlw	@T[1], @C[7], 32-8
	sllw	@T[2], @C[7], 8
	srlw	@T[3], @C[6], 32-8
	or	@C[6], @T[1], @T[0]
	or	@C[7], @T[3], @T[2]	# C[3] = ROL64(A[3][4], 8)

	sllw	@T[0], @C[8], 18
	srlw	@T[1], @C[9], 32-18
	sllw	@T[2], @C[9], 18
	srlw	@T[3], @C[8], 32-18
	or	@C[8], @T[1], @T[0]
	or	@C[9], @T[3], @T[2]	# C[4] = ROL64(A[4][0], 18)
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

#ifdef	__riscv_zbb
	rorw	@C[0], @C[0], 31-13
	rorw	@C[1], @C[1], 32-13
	rorw	@C[2], @C[2], 32-18
	rorw	@C[3], @C[3], 32-18
	rorw	@C[4], @C[4], 32-5
	rorw	@C[5], @C[5], 32-5
	rorw	@C[6], @C[6], 31-7
	rorw	@C[7], @C[7], 32-7
	rorw	@C[8], @C[8], 32-28
	rorw	@C[9], @C[9], 32-28
#else
	sllw	@T[0], @C[1], 27
	srlw	@T[1], @C[0], 32-27
	sllw	@T[2], @C[0], 27
	srlw	@T[3], @C[1], 32-27
	or	@C[0], @T[1], @T[0]
	or	@C[1], @T[3], @T[2]	# C[0] = ROL64(A[0][4], 27)

	sllw	@T[0], @C[3], 4
	srlw	@T[1], @C[2], 32-4
	sllw	@T[2], @C[2], 4
	srlw	@T[3], @C[3], 32-4
	or	@C[2], @T[1], @T[0]
	or	@C[3], @T[3], @T[2]	# C[1] = ROL64(A[1][0], 36)

	sllw	@T[0], @C[4], 10
	srlw	@T[1], @C[5], 32-10
	sllw	@T[2], @C[5], 10
	srlw	@T[3], @C[4], 32-10
	or	@C[4], @T[1], @T[0]
	or	@C[5], @T[3], @T[2]	# C[2] = ROL64(A[2][1], 10)

	sllw	@T[0], @C[7], 15
	srlw	@T[1], @C[6], 32-15
	sllw	@T[2], @C[6], 15
	srlw	@T[3], @C[7], 32-15
	or	@C[6], @T[1], @T[0]
	or	@C[7], @T[3], @T[2]	# C[3] = ROL64(A[3][2], 15)

	sllw	@T[0], @C[9], 24
	srlw	@T[1], @C[8], 32-24
	sllw	@T[2], @C[8], 24
	srlw	@T[3], @C[9], 32-24
	or	@C[8], @T[1], @T[0]
	or	@C[9], @T[3], @T[2]	# C[4] = ROL64(A[4][3], 56)
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
	 cmove	@T[0], $a0		# xchg	$a0, $a1
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
	 cmove	$a0, $a1
	xor	@C[6], @C[6], @D[1]	# flip order
	xor	@C[7], @C[7], @D[0]
	 cmove	$a1, @T[0]
	xor	@C[8], @C[8], @D[2]
	xor	@C[9], @C[9], @D[3]

#ifdef	__riscv_zbb
	rorw	@C[0], @C[0], 32-31
	rorw	@C[1], @C[1], 32-31
	rorw	@C[2], @C[2], 31-27
	rorw	@C[3], @C[3], 32-27
	rorw	@C[4], @C[4], 31-19
	rorw	@C[5], @C[5], 32-19
	rorw	@C[6], @C[6], 31-20
	rorw	@C[7], @C[7], 32-20
	rorw	@C[8], @C[8], 32-1
	rorw	@C[9], @C[9], 32-1
#else
	sllw	@T[0], @C[1], 30
	srlw	@T[1], @C[0], 32-30
	sllw	@T[2], @C[0], 30
	srlw	@T[3], @C[1], 32-30
	or	@C[0], @T[1], @T[0]
	or	@C[1], @T[3], @T[2]	# C[0] = ROL64(A[0][2], 62)

	sllw	@T[0], @C[2], 23
	srlw	@T[1], @C[3], 32-23
	sllw	@T[2], @C[3], 23
	srlw	@T[3], @C[2], 32-23
	or	@C[2], @T[1], @T[0]
	or	@C[3], @T[3], @T[2]	# C[1] = ROL64(A[1][3], 55)

	sllw	@T[0], @C[4], 7
	srlw	@T[1], @C[5], 32-7
	sllw	@T[2], @C[5], 7
	srlw	@T[3], @C[4], 32-7
	or	@C[4], @T[1], @T[0]
	or	@C[5], @T[3], @T[2]	# C[2] = ROL64(A[2][4], 39)

	sllw	@T[0], @C[6], 9
	srlw	@T[1], @C[7], 32-9
	sllw	@T[2], @C[7], 9
	srlw	@T[3], @C[6], 32-9
	or	@C[6], @T[1], @T[0]
	or	@C[7], @T[3], @T[2]	# C[3] = ROL64(A[3][0], 41)

	sllw	@T[0], @C[8], 2
	srlw	@T[1], @C[9], 32-2
	sllw	@T[2], @C[9], 2
	srlw	@T[3], @C[8], 32-2
	or	@C[8], @T[1], @T[0]
	or	@C[9], @T[3], @T[2]	# C[4] = ROL64(A[4][1], 2)
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
	andi	@T[0], $t0, 0xff
	sw	@D[9], $A[4][4]+4($a0)
	bnez	@T[0], .Loop

	caddi	$sp, $sp, 224
	ret
.size	__KeccakF1600, .-__KeccakF1600

.type	KeccakF1600, \@function
KeccakF1600:
	caddi	$sp,  $sp, -__SIZEOF_POINTER__*16
	PUSH	$ra,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*8($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*7($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*6($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*5($sp)
	PUSH	$s10, __SIZEOF_POINTER__*4($sp)
	PUSH	$s11, __SIZEOF_POINTER__*3($sp)

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

	jal	__KeccakF1600

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

	POP	$ra,  __SIZEOF_POINTER__*15($sp)
	POP	$s0,  __SIZEOF_POINTER__*14($sp)
	POP	$s1,  __SIZEOF_POINTER__*13($sp)
	POP	$s2,  __SIZEOF_POINTER__*12($sp)
	POP	$s3,  __SIZEOF_POINTER__*11($sp)
	POP	$s4,  __SIZEOF_POINTER__*10($sp)
	POP	$s5,  __SIZEOF_POINTER__*9($sp)
	POP	$s6,  __SIZEOF_POINTER__*8($sp)
	POP	$s7,  __SIZEOF_POINTER__*7($sp)
	POP	$s8,  __SIZEOF_POINTER__*6($sp)
	POP	$s9,  __SIZEOF_POINTER__*5($sp)
	POP	$s10, __SIZEOF_POINTER__*4($sp)
	POP	$s11, __SIZEOF_POINTER__*3($sp)
	caddi	$sp,  $sp, __SIZEOF_POINTER__*16
	ret
.size	KeccakF1600, .-KeccakF1600
___
{
my ($A_flat, $inp, $len, $bsz) = ($t6, $a1, $a2, $a3);
$code.=<<___;
.globl	SHA3_absorb
.type	SHA3_absorb, \@function
SHA3_absorb:
	caddi	$sp,  $sp, -__SIZEOF_POINTER__*20
	bltu	$len, $bsz, .Labsorb_abort	# len < bsz?
	PUSH	$ra,  __SIZEOF_POINTER__*19($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*18($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*17($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*16($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s10, __SIZEOF_POINTER__*8($sp)
	PUSH	$s11, __SIZEOF_POINTER__*7($sp)

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

	PUSH	$bsz, __SIZEOF_POINTER__*2($sp)

.Loop_absorb:
	sub	$t1, $len, $bsz
	cadd	$t2, $inp, $bsz		# next input block
	PUSH	$t1, __SIZEOF_POINTER__*1($sp)
	PUSH	$t2, __SIZEOF_POINTER__*0($sp)
	cmove	$A_flat, $a0
#ifdef	__riscv_zbb
	lui	$s0, 0x55555
	lui	$s1, 0x33333
	lui	$s2, 0x0f0f1
	lui	$s3, 0x00ff0
	addi	$s0, $s0, 0x555		# 0x55555555
	addi	$s1, $s1, 0x333		# 0x33333333
	addi	$s2, $s2, -0xf1		# 0x0f0f0f0f
	addi	$s3, $s3, 0x0ff		# 0x00ff00ff
	sllw	$s4, $s0, 1		# 0xaaaaaaaa
	sllw	$s5, $s1, 2		# 0xcccccccc
	sllw	$s6, $s2, 4		# 0xf0f0f0f0
	sllw	$s7, $s3, 8		# 0xff00ff00
	lui	$s8, 0xffff0		# 0xffff0000
	srlw	$s9, $s8, 16		# 0x0000ffff
#endif

.Loop_block:
	lbu	$a4, 0($inp)
	lbu	$a5, 4($inp)
	lbu	$a6, 1($inp)
	lbu	$a7, 5($inp)
	lbu	$ra, 2($inp)
	lbu	$t0, 6($inp)
	sllw	$a6, $a6, 8
	lbu	$t1, 3($inp)
	sllw	$a7, $a7, 8
	lbu	$t2, 7($inp)
	sllw	$ra, $ra, 16
	or	$a4, $a4, $a6
	sllw	$t0, $t0, 16
	or	$a5, $a5, $a7
	sllw	$t1, $t1, 24
	or	$a4, $a4, $ra
	sllw	$t2, $t2, 24
	or	$a5, $a5, $t0
	or	$a4, $a4, $t1
	or	$a5, $a5, $t2
	caddi	$inp, $inp, 8

	lw	$s10, 0($A_flat)
	lw	$s11, 4($A_flat)

#ifdef	__riscv_zbb
	and	$t0, $a4, $s0		# t0 = lo & 0x55555555;
	 and	$t1, $a5, $s0		# t1 = hi & 0x55555555;
	srlw	$ra, $t0, 1
	 srlw	$t2, $t1, 1
	or	$t0, $t0, $ra		# t0 |= t0 >> 1;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 1;
	and	$t0, $t0, $s1		# t0 &= 0x33333333;
	 and	$t1, $t1, $s1		# t1 &= 0x33333333;
	srlw	$ra, $t0, 2
	 srlw	$t2, $t1, 2
	or	$t0, $t0, $ra		# t0 |= t0 >> 2;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 2;
	and	$t0, $t0, $s2		# t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s2		# t1 &= 0x0f0f0f0f;
	srlw	$ra, $t0, 4
	 srlw	$t2, $t1, 4
	or	$t0, $t0, $ra		# t0 |= t0 >> 4;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 4;
	and	$t0, $t0, $s3		# t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s3		# t1 &= 0x00ff00ff;
	srlw	$ra, $t0, 8
	 srlw	$t2, $t1, 8
	or	$t0, $t0, $ra		# t0 |= t0 >> 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 8;
	and	$t0, $t0, $s9		# t0 &= 0x0000ffff;
	 sllw	$t1, $t1, 16		# t1 <<= 16;

	and	$a4, $a4, $s4		# lo &= 0xaaaaaaaa;
	 and	$a5, $a5, $s4		# hi &= 0xaaaaaaaa;
	sllw	$ra, $a4, 1
	 sllw	$t2, $a5, 1
	or	$a4, $a4, $ra		# lo |= lo << 1;
	 or	$a5, $a5, $t2		# hi |= hi << 1;
	and	$a4, $a4, $s5		# lo &= 0xcccccccc;
	 and	$a5, $a5, $s5		# hi &= 0xcccccccc;
	sllw	$ra, $a4, 2
	 sllw	$t2, $a5, 2
	or	$a4, $a4, $ra		# lo |= lo << 2;
	 or	$a5, $a5, $t2		# hi |= hi << 2;
	and	$a4, $a4, $s6		# lo &= 0xf0f0f0f0;
	 and	$a5, $a5, $s6		# hi &= 0xf0f0f0f0;
	sllw	$ra, $a4, 4
	 sllw	$t2, $a5, 4
	or	$a4, $a4, $ra		# lo |= lo << 4;
	 or	$a5, $a5, $t2		# hi |= hi << 4;
	and	$a4, $a4, $s7		# lo &= 0xff00ff00;
	 and	$a5, $a5, $s7		# hi &= 0xff00ff00;
	sllw	$ra, $a4, 8
	 sllw	$t2, $a5, 8
	or	$a4, $a4, $ra		# lo |= lo << 8;
	 or	$a5, $a5, $t2		# hi |= hi << 8;
	srlw	$a4, $a4, 16		# lo >>= 16;
	 and	$a5, $a5, $s8		# hi &= 0xffff0000;

	xor	$s10, $s10, $t0		# absorb
	xor	$s11, $s11, $a4
	xor	$s10, $s10, $t1
	xor	$s11, $s11, $a5
#else
	xor	$s10, $s10, $a4
	xor	$s11, $s11, $a5
#endif

	sw	$s10, 0($A_flat)
	addi	$bsz, $bsz, -8
	sw	$s11, 4($A_flat)
	caddi	$A_flat, $A_flat, 8
	bnez	$bsz, .Loop_block

	jal	__KeccakF1600

	POP	$bsz, __SIZEOF_POINTER__*2($sp)
	POP	$len, __SIZEOF_POINTER__*1($sp)
	POP	$inp, __SIZEOF_POINTER__*0($sp)

	bgeu	$len, $bsz, .Loop_absorb

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

	POP	$ra,  __SIZEOF_POINTER__*19($sp)
	POP	$s0,  __SIZEOF_POINTER__*18($sp)
	POP	$s1,  __SIZEOF_POINTER__*17($sp)
	POP	$s2,  __SIZEOF_POINTER__*16($sp)
	POP	$s3,  __SIZEOF_POINTER__*15($sp)
	POP	$s4,  __SIZEOF_POINTER__*14($sp)
	POP	$s5,  __SIZEOF_POINTER__*13($sp)
	POP	$s6,  __SIZEOF_POINTER__*12($sp)
	POP	$s7,  __SIZEOF_POINTER__*11($sp)
	POP	$s8,  __SIZEOF_POINTER__*10($sp)
	POP	$s9,  __SIZEOF_POINTER__*9($sp)
	POP	$s10, __SIZEOF_POINTER__*8($sp)
	POP	$s11, __SIZEOF_POINTER__*7($sp)
.Labsorb_abort:
	mv	$a0, $len		# return value
	caddi	$sp, $sp, __SIZEOF_POINTER__*20
	ret
.size	SHA3_absorb, .-SHA3_absorb
___
}
{
my ($A_flat, $out, $len, $bsz) = ($t6, $a1, $a2, $a3);
$code.=<<___;
.globl	SHA3_squeeze
.align	5
.type	SHA3_squeeze, \@function
SHA3_squeeze:
	caddi	$sp,  $sp, -__SIZEOF_POINTER__*16
	PUSH	$ra,  __SIZEOF_POINTER__*15($sp)
	PUSH	$s0,  __SIZEOF_POINTER__*14($sp)
	PUSH	$s1,  __SIZEOF_POINTER__*13($sp)
	PUSH	$s2,  __SIZEOF_POINTER__*12($sp)
	PUSH	$s3,  __SIZEOF_POINTER__*11($sp)
	PUSH	$s4,  __SIZEOF_POINTER__*10($sp)
	PUSH	$s5,  __SIZEOF_POINTER__*9($sp)
	PUSH	$s6,  __SIZEOF_POINTER__*8($sp)
	PUSH	$s7,  __SIZEOF_POINTER__*7($sp)
	PUSH	$s8,  __SIZEOF_POINTER__*6($sp)
	PUSH	$s9,  __SIZEOF_POINTER__*5($sp)
	PUSH	$s10, __SIZEOF_POINTER__*4($sp)
	PUSH	$s11, __SIZEOF_POINTER__*3($sp)

	PUSH	$bsz, __SIZEOF_POINTER__*2($sp)
	cmove	$A_flat, $a0

#ifdef	__riscv_zbb
	lui	$s4, 0x55555
	lui	$s5, 0x33333
	lui	$s6, 0x0f0f1
	lui	$s7, 0x00ff0
	addi	$s4, $s4, 0x555		# 0x55555555
	addi	$s5, $s5, 0x333		# 0x33333333
	addi	$s6, $s6, -0xf1		# 0x0f0f0f0f
	addi	$s7, $s7, 0x0ff		# 0x00ff00ff
	lui	$s2, 0xffff0		# 0xffff0000
	sllw	$s8, $s4, 1		# 0xaaaaaaaa
	sllw	$s9, $s5, 2		# 0xcccccccc
	sllw	$s10, $s6, 4		# 0xf0f0f0f0
	sllw	$s11, $s7, 8		# 0xff00ff00
	srlw	$s3, $s2, 16		# 0x0000ffff
#endif

.Loop_squeeze:
	lw	$a4, 0($A_flat)
	lw	$a5, 4($A_flat)
	caddi	$A_flat, $A_flat, 8

#ifdef	__riscv_zbb
	and	$t0, $a4, $s3		# t0 = lo & 0x0000ffff;
	 sllw	$t1, $a5, 16		# t1 = hi << 16;
	sllw	$ra, $t0, 8
	 srlw	$t2, $t1, 8
	or	$t0, $t0, $ra		# t0 |= t0 << 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 1;
	and	$t0, $t0, $s7		# t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s11		# t1 &= 0xff00ff00;
	sllw	$ra, $t0, 4
	 srlw	$t2, $t1, 4
	or	$t0, $t0, $ra		# t0 |= t0 << 4;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 2;
	and	$t0, $t0, $s6		# t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s10		# t1 &= 0xf0f0f0f0;
	sllw	$ra, $t0, 2
	 srlw	$t2, $t1, 2
	or	$t0, $t0, $ra		# t0 |= t0 << 2;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 4;
	and	$t0, $t0, $s5		# t0 &= 0x33333333;
	 and	$t1, $t1, $s9		# t1 &= 0xcccccccc;
	sllw	$ra, $t0, 1
	 srlw	$t2, $t1, 1
	or	$t0, $t0, $ra		# t0 |= t0 >> 8;
	 or	$t1, $t1, $t2		# t1 |= t1 >> 8;
	and	$t0, $t0, $s4		# t0 &= 0x55555555;
	 and	$t1, $t1, $s8		# t1 &= 0xaaaaaaaa;

	srlw	$a4, $a4, 16		# lo >>= 16;
	 and	$a5, $a5, $s2		# hi &= 0xffff0000;
	sllw	$ra, $a4, 8
	 srlw	$t2, $a5, 8
	or	$a4, $a4, $ra		# lo |= lo << 8;
	 or	$a5, $a5, $t2		# hi |= hi >> 8;
	and	$a4, $a4, $s7		# lo &= 0x00ff00ff;
	 and	$a5, $a5, $s11		# hi &= 0xff00ff00;
	sllw	$ra, $a4, 4
	 srlw	$t2, $a5, 4
	or	$a4, $a4, $ra		# lo |= lo << 4;
	 or	$a5, $a5, $t2		# hi |= hi >> 4;
	and	$a4, $a4, $s6		# lo &= 0x0f0f0f0f;
	 and	$a5, $a5, $s10		# hi &= 0xf0f0f0f0;
	sllw	$ra, $a4, 2
	 srlw	$t2, $a5, 2
	or	$a4, $a4, $ra		# lo |= lo << 2;
	 or	$a5, $a5, $t2		# hi |= hi >> 2;
	and	$a4, $a4, $s5		# lo &= 0x33333333;
	 and	$a5, $a5, $s9		# hi &= 0xcccccccc;
	sllw	$ra, $a4, 1
	 srlw	$t2, $a5, 1
	or	$a4, $a4, $ra		# lo |= lo << 1;
	 or	$a5, $a5, $t2		# hi |= hi >> 1;
	and	$a4, $a4, $s4		# lo &= 0x55555555;
	 and	$a5, $a5, $s8		# hi &= 0xaaaaaaaa;

	or	$a5, $a5, $a4
	or	$a4, $t0, $t1
#endif
	sltiu	$ra, $len, 4
	bnez	$ra, .Lsqueeze_tail

	srlw	$a6, $a4, 8
	sb	$a4, 0($out)
	srlw	$a7, $a4, 16
	sb	$a6, 1($out)
	srlw	$t0, $a4, 24
	sb	$a7, 2($out)
	addi	$len, $len, -4
	sb	$t0, 3($out)
	sltiu	$ra, $len, 4
	caddi	$out, $out, 4
	mv	$a4, $a5
	bnez	$ra, .Lsqueeze_tail

	srlw	$a6, $a4, 8
	sb	$a4, 0($out)
	srlw	$a7, $a4, 16
	sb	$a6, 1($out)
	srlw	$t0, $a4, 24
	sb	$a7, 2($out)
	addi	$len, $len, -4
	sb	$t0, 3($out)
	caddi	$out, $out, 4
	beqz	$len, .Lsqueeze_done

	addi	$bsz, $bsz, -8
	bnez	$bsz, .Loop_squeeze

	PUSH	$len, __SIZEOF_POINTER__*1($sp)
	PUSH	$out, __SIZEOF_POINTER__*0($sp)

	jal	KeccakF1600

	POP	$out, __SIZEOF_POINTER__*0($sp)
	POP	$len, __SIZEOF_POINTER__*1($sp)
	POP	$bsz, __SIZEOF_POINTER__*2($sp)
	cmove	$A_flat, $a0
	j	.Loop_squeeze

.Lsqueeze_tail:
	beqz	$len, .Lsqueeze_done
	addi	$len, $len, -1
	sb	$a4, 0($out)
	caddi	$out, $out, 1
	srlw	$a4, $a4, 8
	j	.Lsqueeze_tail

.Lsqueeze_done:
	POP	$ra,  __SIZEOF_POINTER__*15($sp)
	POP	$s0,  __SIZEOF_POINTER__*14($sp)
	POP	$s1,  __SIZEOF_POINTER__*13($sp)
	POP	$s2,  __SIZEOF_POINTER__*12($sp)
	POP	$s3,  __SIZEOF_POINTER__*11($sp)
	POP	$s4,  __SIZEOF_POINTER__*10($sp)
	POP	$s5,  __SIZEOF_POINTER__*9($sp)
	POP	$s6,  __SIZEOF_POINTER__*8($sp)
	POP	$s7,  __SIZEOF_POINTER__*7($sp)
	POP	$s8,  __SIZEOF_POINTER__*6($sp)
	POP	$s9,  __SIZEOF_POINTER__*5($sp)
	POP	$s10, __SIZEOF_POINTER__*4($sp)
	POP	$s11, __SIZEOF_POINTER__*3($sp)
	caddi	$sp,  $sp, __SIZEOF_POINTER__*16
	ret
.size	SHA3_squeeze, .-SHA3_squeeze
___
}
$code.=<<___;
.section	.rodata
.align 8	# strategic alignment and padding that allows to use
		# address value as loop termination condition...
	.word	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
iotas:
#ifdef	__riscv_zbb
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
#else
	.word	0x00000001, 0x00000000
	.word	0x00008082, 0x00000000
	.word	0x0000808a, 0x80000000
	.word	0x80008000, 0x80000000
	.word	0x0000808b, 0x00000000
	.word	0x80000001, 0x00000000
	.word	0x80008081, 0x80000000
	.word	0x00008009, 0x80000000
	.word	0x0000008a, 0x00000000
	.word	0x00000088, 0x00000000
	.word	0x80008009, 0x00000000
	.word	0x8000000a, 0x00000000
	.word	0x8000808b, 0x00000000
	.word	0x0000008b, 0x80000000
	.word	0x00008089, 0x80000000
	.word	0x00008003, 0x80000000
	.word	0x00008002, 0x80000000
	.word	0x00000080, 0x80000000
	.word	0x0000800a, 0x00000000
	.word	0x8000000a, 0x80000000
	.word	0x80008081, 0x80000000
	.word	0x00008080, 0x80000000
	.word	0x80000001, 0x00000000
	.word	0x80008008, 0x80000000
#endif
.string	"Keccak-1600 absorb and squeeze for RISC-V, CRYPTOGAMS by \@dot-asm"
___
}}}

foreach (split("\n", $code)) {
    if ($flavour =~ "cheri") {
	s/\(x([0-9]+)\)/(c$1)/ and s/\b([ls][bhwd]u?)\b/c$1/;
	s/\b(PUSH|POP|cllc)(\s+)x([0-9]+)/$1$2c$3/ or
	s/\b(ret|jal)\b/c$1/;
	s/\bcaddi?\b/cincoffset/ and s/\bx([0-9]+,)/c$1/g or
	m/\bcmove\b/ and s/\bx([0-9]+)/c$1/g;
    } else {
	s/\bcaddi?\b/add/ or
	s/\bcmove\b/mv/ or
	s/\bcllc\b/lla/;
    }
    print $_, "\n";
}

close STDOUT;
