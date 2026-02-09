#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov , @dot-asm, originally for the OpenSSL
# project.
# ====================================================================
#
# Keccak-1600 for PPC64.
#
# June 2017.
#
# This is straightforward KECCAK_1X_ALT implementation that works on
# *any* PPC64. Then PowerISA 2.07 adds 2x64-bit vector rotate, and
# it's possible to achieve performance better than below, but that is
# naturally option only for POWER8 and successors...
#
# March 2019.
#
# Add 32-bit KECCAK_2X with bit interleaving, and C[] and D[] in
# registers.
#
######################################################################
# Numbers are cycles per processed byte for r=1088(*).
#
#			-m32		-m64
# Freescale e300c1	72/+90%		-
# PPC74x0/G4		44/+190%	-
# PPC970/G5		36/+200%	14.0/+130%
# POWER7		28/+60%		9.7/+110%
# POWER8		-		9.6(**)/+120%
# POWER9		-		7.4(**)/+80%
#
# (*)	Corresponds to SHA3-256. Percentage after slash is improvement
#	over gcc-4.x-generated code. Newer compilers do much better
#	(but watch out for them generating code specific to processor
#	they execute on).
# (**)	These results are for aligned input on little-endian system,
#	misalgined and big-endian results are ~10% worse.

$flavour = shift;

if ($flavour =~ /64/) {
	$SIZE_T	=8;
	$LRSAVE	=2*$SIZE_T;
	$UCMP	="cmpld";
	$STU	="stdu";
	$POP	="ld";
	$PUSH	="std";
} else {
	$SIZE_T	=4;
	$LRSAVE	=$SIZE_T;
	$UCMP	="cmplw";
	$STU	="stwu";
	$POP	="lwz";
	$PUSH	="stw";
}

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour ".shift || die "can't call $xlate: $!";

$FRAME=6*$SIZE_T+32+24*$SIZE_T;
$LOCALS=6*$SIZE_T;
$TEMP=$LOCALS+6*$SIZE_T;

my $sp ="r1";

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

if ($flavour =~ /64/) {{{
########################################################################
# 64-bit code path...
#
my @A = map([ "r$_", "r".($_+1), "r".($_+2), "r".($_+3), "r".($_+4) ],
            (7, 12, 17, 22, 27));
   $A[1][1] = "r6"; # r13 is reserved

my @C = map("r$_", (0,3,4,5));

$code.=<<___;
.text

.type	KeccakF1600_int,\@function
.align	5
KeccakF1600_int:
	li	r0,24
	mtctr	r0
	b	.Loop
.align	4
.Loop:
	xor	$C[0],$A[0][0],$A[1][0]		; Theta
	std	$A[0][4],`$TEMP+0`($sp)
	xor	$C[1],$A[0][1],$A[1][1]
	std	$A[1][4],`$TEMP+8`($sp)
	xor	$C[2],$A[0][2],$A[1][2]
	std	$A[2][4],`$TEMP+16`($sp)
	xor	$C[3],$A[0][3],$A[1][3]
	std	$A[3][4],`$TEMP+24`($sp)
___
	$C[4]=$A[0][4];
	$C[5]=$A[1][4];
	$C[6]=$A[2][4];
	$C[7]=$A[3][4];
$code.=<<___;
	xor	$C[4],$A[0][4],$A[1][4]
	xor	$C[0],$C[0],$A[2][0]
	xor	$C[1],$C[1],$A[2][1]
	xor	$C[2],$C[2],$A[2][2]
	xor	$C[3],$C[3],$A[2][3]
	xor	$C[4],$C[4],$A[2][4]
	xor	$C[0],$C[0],$A[3][0]
	xor	$C[1],$C[1],$A[3][1]
	xor	$C[2],$C[2],$A[3][2]
	xor	$C[3],$C[3],$A[3][3]
	xor	$C[4],$C[4],$A[3][4]
	xor	$C[0],$C[0],$A[4][0]
	xor	$C[2],$C[2],$A[4][2]
	xor	$C[1],$C[1],$A[4][1]
	xor	$C[3],$C[3],$A[4][3]
	rotldi	$C[5],$C[2],1
	xor	$C[4],$C[4],$A[4][4]
	rotldi	$C[6],$C[3],1
	xor	$C[5],$C[5],$C[0]
	rotldi	$C[7],$C[4],1

	xor	$A[0][1],$A[0][1],$C[5]
	xor	$A[1][1],$A[1][1],$C[5]
	xor	$A[2][1],$A[2][1],$C[5]
	xor	$A[3][1],$A[3][1],$C[5]
	xor	$A[4][1],$A[4][1],$C[5]

	rotldi	$C[5],$C[0],1
	xor	$C[6],$C[6],$C[1]
	xor	$C[2],$C[2],$C[7]
	rotldi	$C[7],$C[1],1
	xor	$C[3],$C[3],$C[5]
	xor	$C[4],$C[4],$C[7]

	xor	$C[1],   $A[0][2],$C[6]			;mr	$C[1],$A[0][2]
	xor	$A[1][2],$A[1][2],$C[6]
	xor	$A[2][2],$A[2][2],$C[6]
	xor	$A[3][2],$A[3][2],$C[6]
	xor	$A[4][2],$A[4][2],$C[6]

	xor	$A[0][0],$A[0][0],$C[4]
	xor	$A[1][0],$A[1][0],$C[4]
	xor	$A[2][0],$A[2][0],$C[4]
	xor	$A[3][0],$A[3][0],$C[4]
	xor	$A[4][0],$A[4][0],$C[4]
___
	$C[4]=undef;
	$C[5]=undef;
	$C[6]=undef;
	$C[7]=undef;
$code.=<<___;
	ld	$A[0][4],`$TEMP+0`($sp)
	xor	$C[0],   $A[0][3],$C[2]			;mr	$C[0],$A[0][3]
	ld	$A[1][4],`$TEMP+8`($sp)
	xor	$A[1][3],$A[1][3],$C[2]
	ld	$A[2][4],`$TEMP+16`($sp)
	xor	$A[2][3],$A[2][3],$C[2]
	ld	$A[3][4],`$TEMP+24`($sp)
	xor	$A[3][3],$A[3][3],$C[2]
	xor	$A[4][3],$A[4][3],$C[2]

	xor	$C[2],   $A[0][4],$C[3]			;mr	$C[2],$A[0][4]
	xor	$A[1][4],$A[1][4],$C[3]
	xor	$A[2][4],$A[2][4],$C[3]
	xor	$A[3][4],$A[3][4],$C[3]
	xor	$A[4][4],$A[4][4],$C[3]

	mr	$C[3],$A[0][1]				; Rho+Pi
	rotldi	$A[0][1],$A[1][1],$rhotates[1][1]
	;mr	$C[1],$A[0][2]
	rotldi	$A[0][2],$A[2][2],$rhotates[2][2]
	;mr	$C[0],$A[0][3]
	rotldi	$A[0][3],$A[3][3],$rhotates[3][3]
	;mr	$C[2],$A[0][4]
	rotldi	$A[0][4],$A[4][4],$rhotates[4][4]

	rotldi	$A[1][1],$A[1][4],$rhotates[1][4]
	rotldi	$A[2][2],$A[2][3],$rhotates[2][3]
	rotldi	$A[3][3],$A[3][2],$rhotates[3][2]
	rotldi	$A[4][4],$A[4][1],$rhotates[4][1]

	rotldi	$A[1][4],$A[4][2],$rhotates[4][2]
	rotldi	$A[2][3],$A[3][4],$rhotates[3][4]
	rotldi	$A[3][2],$A[2][1],$rhotates[2][1]
	rotldi	$A[4][1],$A[1][3],$rhotates[1][3]

	rotldi	$A[4][2],$A[2][4],$rhotates[2][4]
	rotldi	$A[3][4],$A[4][3],$rhotates[4][3]
	rotldi	$A[2][1],$A[1][2],$rhotates[1][2]
	rotldi	$A[1][3],$A[3][1],$rhotates[3][1]

	rotldi	$A[2][4],$A[4][0],$rhotates[4][0]
	rotldi	$A[4][3],$A[3][0],$rhotates[3][0]
	rotldi	$A[1][2],$A[2][0],$rhotates[2][0]
	rotldi	$A[3][1],$A[1][0],$rhotates[1][0]

	rotldi	$A[1][0],$C[0],$rhotates[0][3]
	rotldi	$A[2][0],$C[3],$rhotates[0][1]
	rotldi	$A[3][0],$C[2],$rhotates[0][4]
	rotldi	$A[4][0],$C[1],$rhotates[0][2]

	andc	$C[0],$A[0][2],$A[0][1]			; Chi+Iota
	andc	$C[1],$A[0][3],$A[0][2]
	andc	$C[2],$A[0][0],$A[0][4]
	andc	$C[3],$A[0][1],$A[0][0]
	xor	$A[0][0],$A[0][0],$C[0]
	andc	$C[0],$A[0][4],$A[0][3]
	xor	$A[0][1],$A[0][1],$C[1]
	 ld	$C[1],`$LOCALS+4*$SIZE_T`($sp)
	xor	$A[0][3],$A[0][3],$C[2]
	xor	$A[0][4],$A[0][4],$C[3]
	xor	$A[0][2],$A[0][2],$C[0]
	 ldu	$C[3],8($C[1])				; Iota[i++]

	andc	$C[0],$A[1][2],$A[1][1]
	 std	$C[1],`$LOCALS+4*$SIZE_T`($sp)
	andc	$C[1],$A[1][3],$A[1][2]
	andc	$C[2],$A[1][0],$A[1][4]
	 xor	$A[0][0],$A[0][0],$C[3]			; A[0][0] ^= Iota
	andc	$C[3],$A[1][1],$A[1][0]
	xor	$A[1][0],$A[1][0],$C[0]
	andc	$C[0],$A[1][4],$A[1][3]
	xor	$A[1][1],$A[1][1],$C[1]
	xor	$A[1][3],$A[1][3],$C[2]
	xor	$A[1][4],$A[1][4],$C[3]
	xor	$A[1][2],$A[1][2],$C[0]

	andc	$C[0],$A[2][2],$A[2][1]
	andc	$C[1],$A[2][3],$A[2][2]
	andc	$C[2],$A[2][0],$A[2][4]
	andc	$C[3],$A[2][1],$A[2][0]
	xor	$A[2][0],$A[2][0],$C[0]
	andc	$C[0],$A[2][4],$A[2][3]
	xor	$A[2][1],$A[2][1],$C[1]
	xor	$A[2][3],$A[2][3],$C[2]
	xor	$A[2][4],$A[2][4],$C[3]
	xor	$A[2][2],$A[2][2],$C[0]

	andc	$C[0],$A[3][2],$A[3][1]
	andc	$C[1],$A[3][3],$A[3][2]
	andc	$C[2],$A[3][0],$A[3][4]
	andc	$C[3],$A[3][1],$A[3][0]
	xor	$A[3][0],$A[3][0],$C[0]
	andc	$C[0],$A[3][4],$A[3][3]
	xor	$A[3][1],$A[3][1],$C[1]
	xor	$A[3][3],$A[3][3],$C[2]
	xor	$A[3][4],$A[3][4],$C[3]
	xor	$A[3][2],$A[3][2],$C[0]

	andc	$C[0],$A[4][2],$A[4][1]
	andc	$C[1],$A[4][3],$A[4][2]
	andc	$C[2],$A[4][0],$A[4][4]
	andc	$C[3],$A[4][1],$A[4][0]
	xor	$A[4][0],$A[4][0],$C[0]
	andc	$C[0],$A[4][4],$A[4][3]
	xor	$A[4][1],$A[4][1],$C[1]
	xor	$A[4][3],$A[4][3],$C[2]
	xor	$A[4][4],$A[4][4],$C[3]
	xor	$A[4][2],$A[4][2],$C[0]

	bdnz	.Loop

	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
.size	KeccakF1600_int,.-KeccakF1600_int

.type	KeccakF1600,\@function
.align	5
KeccakF1600:
	$STU	$sp,-$FRAME($sp)
	mflr	r0
	$PUSH	r14,`$FRAME-$SIZE_T*18`($sp)
	$PUSH	r15,`$FRAME-$SIZE_T*17`($sp)
	$PUSH	r16,`$FRAME-$SIZE_T*16`($sp)
	$PUSH	r17,`$FRAME-$SIZE_T*15`($sp)
	$PUSH	r18,`$FRAME-$SIZE_T*14`($sp)
	$PUSH	r19,`$FRAME-$SIZE_T*13`($sp)
	$PUSH	r20,`$FRAME-$SIZE_T*12`($sp)
	$PUSH	r21,`$FRAME-$SIZE_T*11`($sp)
	$PUSH	r22,`$FRAME-$SIZE_T*10`($sp)
	$PUSH	r23,`$FRAME-$SIZE_T*9`($sp)
	$PUSH	r24,`$FRAME-$SIZE_T*8`($sp)
	$PUSH	r25,`$FRAME-$SIZE_T*7`($sp)
	$PUSH	r26,`$FRAME-$SIZE_T*6`($sp)
	$PUSH	r27,`$FRAME-$SIZE_T*5`($sp)
	$PUSH	r28,`$FRAME-$SIZE_T*4`($sp)
	$PUSH	r29,`$FRAME-$SIZE_T*3`($sp)
	$PUSH	r30,`$FRAME-$SIZE_T*2`($sp)
	$PUSH	r31,`$FRAME-$SIZE_T*1`($sp)
	$PUSH	r0,`$FRAME+$LRSAVE`($sp)

	bl	PICmeup
	subi	r12,r12,8			; prepare for ldu

	$PUSH	r3,`$LOCALS+0*$SIZE_T`($sp)
	;$PUSH	r4,`$LOCALS+1*$SIZE_T`($sp)
	;$PUSH	r5,`$LOCALS+2*$SIZE_T`($sp)
	;$PUSH	r6,`$LOCALS+3*$SIZE_T`($sp)
	$PUSH	r12,`$LOCALS+4*$SIZE_T`($sp)

	ld	$A[0][0],`8*0`(r3)		; load A[5][5]
	ld	$A[0][1],`8*1`(r3)
	ld	$A[0][2],`8*2`(r3)
	ld	$A[0][3],`8*3`(r3)
	ld	$A[0][4],`8*4`(r3)
	ld	$A[1][0],`8*5`(r3)
	ld	$A[1][1],`8*6`(r3)
	ld	$A[1][2],`8*7`(r3)
	ld	$A[1][3],`8*8`(r3)
	ld	$A[1][4],`8*9`(r3)
	ld	$A[2][0],`8*10`(r3)
	ld	$A[2][1],`8*11`(r3)
	ld	$A[2][2],`8*12`(r3)
	ld	$A[2][3],`8*13`(r3)
	ld	$A[2][4],`8*14`(r3)
	ld	$A[3][0],`8*15`(r3)
	ld	$A[3][1],`8*16`(r3)
	ld	$A[3][2],`8*17`(r3)
	ld	$A[3][3],`8*18`(r3)
	ld	$A[3][4],`8*19`(r3)
	ld	$A[4][0],`8*20`(r3)
	ld	$A[4][1],`8*21`(r3)
	ld	$A[4][2],`8*22`(r3)
	ld	$A[4][3],`8*23`(r3)
	ld	$A[4][4],`8*24`(r3)

	bl	KeccakF1600_int

	$POP	r3,`$LOCALS+0*$SIZE_T`($sp)
	std	$A[0][0],`8*0`(r3)		; return A[5][5]
	std	$A[0][1],`8*1`(r3)
	std	$A[0][2],`8*2`(r3)
	std	$A[0][3],`8*3`(r3)
	std	$A[0][4],`8*4`(r3)
	std	$A[1][0],`8*5`(r3)
	std	$A[1][1],`8*6`(r3)
	std	$A[1][2],`8*7`(r3)
	std	$A[1][3],`8*8`(r3)
	std	$A[1][4],`8*9`(r3)
	std	$A[2][0],`8*10`(r3)
	std	$A[2][1],`8*11`(r3)
	std	$A[2][2],`8*12`(r3)
	std	$A[2][3],`8*13`(r3)
	std	$A[2][4],`8*14`(r3)
	std	$A[3][0],`8*15`(r3)
	std	$A[3][1],`8*16`(r3)
	std	$A[3][2],`8*17`(r3)
	std	$A[3][3],`8*18`(r3)
	std	$A[3][4],`8*19`(r3)
	std	$A[4][0],`8*20`(r3)
	std	$A[4][1],`8*21`(r3)
	std	$A[4][2],`8*22`(r3)
	std	$A[4][3],`8*23`(r3)
	std	$A[4][4],`8*24`(r3)

	$POP	r0,`$FRAME+$LRSAVE`($sp)
	$POP	r14,`$FRAME-$SIZE_T*18`($sp)
	$POP	r15,`$FRAME-$SIZE_T*17`($sp)
	$POP	r16,`$FRAME-$SIZE_T*16`($sp)
	$POP	r17,`$FRAME-$SIZE_T*15`($sp)
	$POP	r18,`$FRAME-$SIZE_T*14`($sp)
	$POP	r19,`$FRAME-$SIZE_T*13`($sp)
	$POP	r20,`$FRAME-$SIZE_T*12`($sp)
	$POP	r21,`$FRAME-$SIZE_T*11`($sp)
	$POP	r22,`$FRAME-$SIZE_T*10`($sp)
	$POP	r23,`$FRAME-$SIZE_T*9`($sp)
	$POP	r24,`$FRAME-$SIZE_T*8`($sp)
	$POP	r25,`$FRAME-$SIZE_T*7`($sp)
	$POP	r26,`$FRAME-$SIZE_T*6`($sp)
	$POP	r27,`$FRAME-$SIZE_T*5`($sp)
	$POP	r28,`$FRAME-$SIZE_T*4`($sp)
	$POP	r29,`$FRAME-$SIZE_T*3`($sp)
	$POP	r30,`$FRAME-$SIZE_T*2`($sp)
	$POP	r31,`$FRAME-$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,4,1,0x80,18,1,0
	.long	0
.size	KeccakF1600,.-KeccakF1600

.type	dword_le_load,\@function
.align	5
dword_le_load:
	lbz	r0,1(r3)
	lbz	r4,2(r3)
	lbz	r5,3(r3)
	insrdi	r0,r4,8,48
	lbz	r4,4(r3)
	insrdi	r0,r5,8,40
	lbz	r5,5(r3)
	insrdi	r0,r4,8,32
	lbz	r4,6(r3)
	insrdi	r0,r5,8,24
	lbz	r5,7(r3)
	insrdi	r0,r4,8,16
	lbzu	r4,8(r3)
	insrdi	r0,r5,8,8
	insrdi	r0,r4,8,0
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,1,0
	.long	0
.size	dword_le_load,.-dword_le_load

.globl	SHA3_absorb
.type	SHA3_absorb,\@function
.align	5
SHA3_absorb:
	$STU	$sp,-$FRAME($sp)
	mflr	r0
	$PUSH	r14,`$FRAME-$SIZE_T*18`($sp)
	$PUSH	r15,`$FRAME-$SIZE_T*17`($sp)
	$PUSH	r16,`$FRAME-$SIZE_T*16`($sp)
	$PUSH	r17,`$FRAME-$SIZE_T*15`($sp)
	$PUSH	r18,`$FRAME-$SIZE_T*14`($sp)
	$PUSH	r19,`$FRAME-$SIZE_T*13`($sp)
	$PUSH	r20,`$FRAME-$SIZE_T*12`($sp)
	$PUSH	r21,`$FRAME-$SIZE_T*11`($sp)
	$PUSH	r22,`$FRAME-$SIZE_T*10`($sp)
	$PUSH	r23,`$FRAME-$SIZE_T*9`($sp)
	$PUSH	r24,`$FRAME-$SIZE_T*8`($sp)
	$PUSH	r25,`$FRAME-$SIZE_T*7`($sp)
	$PUSH	r26,`$FRAME-$SIZE_T*6`($sp)
	$PUSH	r27,`$FRAME-$SIZE_T*5`($sp)
	$PUSH	r28,`$FRAME-$SIZE_T*4`($sp)
	$PUSH	r29,`$FRAME-$SIZE_T*3`($sp)
	$PUSH	r30,`$FRAME-$SIZE_T*2`($sp)
	$PUSH	r31,`$FRAME-$SIZE_T*1`($sp)
	$PUSH	r0,`$FRAME+$LRSAVE`($sp)

	bl	PICmeup
	subi	r12,r12,8			; prepare for ldu

	$PUSH	r3,`$LOCALS+0*$SIZE_T`($sp)	; save A[][]
	$PUSH	r4,`$LOCALS+1*$SIZE_T`($sp)	; save inp
	$PUSH	r5,`$LOCALS+2*$SIZE_T`($sp)	; save len
	$PUSH	r6,`$LOCALS+3*$SIZE_T`($sp)	; save bsz
	mr	r0,r6
	$PUSH	r12,`$LOCALS+4*$SIZE_T`($sp)

	ld	$A[0][0],`8*0`(r3)		; load A[5][5]
	ld	$A[0][1],`8*1`(r3)
	ld	$A[0][2],`8*2`(r3)
	ld	$A[0][3],`8*3`(r3)
	ld	$A[0][4],`8*4`(r3)
	ld	$A[1][0],`8*5`(r3)
	ld	$A[1][1],`8*6`(r3)
	ld	$A[1][2],`8*7`(r3)
	ld	$A[1][3],`8*8`(r3)
	ld	$A[1][4],`8*9`(r3)
	ld	$A[2][0],`8*10`(r3)
	ld	$A[2][1],`8*11`(r3)
	ld	$A[2][2],`8*12`(r3)
	ld	$A[2][3],`8*13`(r3)
	ld	$A[2][4],`8*14`(r3)
	ld	$A[3][0],`8*15`(r3)
	ld	$A[3][1],`8*16`(r3)
	ld	$A[3][2],`8*17`(r3)
	ld	$A[3][3],`8*18`(r3)
	ld	$A[3][4],`8*19`(r3)
	ld	$A[4][0],`8*20`(r3)
	ld	$A[4][1],`8*21`(r3)
	ld	$A[4][2],`8*22`(r3)
	ld	$A[4][3],`8*23`(r3)
	ld	$A[4][4],`8*24`(r3)
___
$code.=<<___	if ($flavour =~ /le/);
	andi.	r3,r4,7				; see if inp is aligned
	bne	.Lmisaligned

.Loop_aligned:
	$UCMP	r5,r0				; len < bsz?
	blt	.Labsorbed

	sub	r5,r5,r0			; len -= bsz
	cmplwi	cr0,r0,104
	cmplwi	cr1,r0,144
	$PUSH	r5,`$LOCALS+2*$SIZE_T`($sp)	; save len

	ld	r3,`8*0`(r4)
	xor	$A[0][0],$A[0][0],r3
	ld	r3,`8*1`(r4)
	xor	$A[0][1],$A[0][1],r3
	ld	r3,`8*2`(r4)
	xor	$A[0][2],$A[0][2],r3
	ld	r3,`8*3`(r4)
	xor	$A[0][3],$A[0][3],r3
	ld	r3,`8*4`(r4)
	xor	$A[0][4],$A[0][4],r3
	ld	r3,`8*5`(r4)
	xor	$A[1][0],$A[1][0],r3
	ld	r3,`8*6`(r4)
	xor	$A[1][1],$A[1][1],r3
	ld	r3,`8*7`(r4)
	xor	$A[1][2],$A[1][2],r3
	ld	r3,`8*8`(r4)
	xor	$A[1][3],$A[1][3],r3
	blt	.Lprocess_aligned

	ld	r3,`8*9`(r4)
	xor	$A[1][4],$A[1][4],r3
	ld	r3,`8*10`(r4)
	xor	$A[2][0],$A[2][0],r3
	ld	r3,`8*11`(r4)
	xor	$A[2][1],$A[2][1],r3
	ld	r3,`8*12`(r4)
	xor	$A[2][2],$A[2][2],r3
	beq	.Lprocess_aligned

	ld	r3,`8*13`(r4)
	xor	$A[2][3],$A[2][3],r3
	ld	r3,`8*14`(r4)
	xor	$A[2][4],$A[2][4],r3
	ld	r3,`8*15`(r4)
	xor	$A[3][0],$A[3][0],r3
	ld	r3,`8*16`(r4)
	xor	$A[3][1],$A[3][1],r3
	blt	cr1,.Lprocess_aligned

	ld	r3,`8*17`(r4)
	xor	$A[3][2],$A[3][2],r3
	beq	cr1,.Lprocess_aligned

	ld	r3,`8*18`(r4)
	xor	$A[3][3],$A[3][3],r3
	ld	r3,`8*19`(r4)
	xor	$A[3][4],$A[3][4],r3
	ld	r3,`8*20`(r4)
	xor	$A[4][0],$A[4][0],r3

.Lprocess_aligned:
	add	r4,r4,r0			; inp += bsz
	$PUSH	r4,`$LOCALS+1*$SIZE_T`($sp)	; save inp

	bl	KeccakF1600_int

	$POP	r3,`$LOCALS+4*$SIZE_T`($sp)	; pull iotas[24]
	$POP	r0,`$LOCALS+3*$SIZE_T`($sp)	; restore bsz
	$POP	r5,`$LOCALS+2*$SIZE_T`($sp)	; restore len
	$POP	r4,`$LOCALS+1*$SIZE_T`($sp)	; restore inp
	addic	r3,r3,`-8*24`			; rewind iotas
	$PUSH	r3,`$LOCALS+4*$SIZE_T`($sp)

	b	.Loop_aligned

.Lmisaligned:
___
$code.=<<___;
	subi	r3,r4,1				; prepare for lbzu
	b	.Loop_absorb

.align	4
.Loop_absorb:
	$UCMP	r5,r0				; len < bsz?
	blt	.Labsorbed

	sub	r5,r5,r0			; len -= bsz
	cmplwi	cr0,r0,104
	cmplwi	cr1,r0,144
	$PUSH	r5,`$LOCALS+2*$SIZE_T`($sp)	; save len

	bl	dword_le_load			; *inp++
	xor	$A[0][0],$A[0][0],r0
	bl	dword_le_load			; *inp++
	xor	$A[0][1],$A[0][1],r0
	bl	dword_le_load			; *inp++
	xor	$A[0][2],$A[0][2],r0
	bl	dword_le_load			; *inp++
	xor	$A[0][3],$A[0][3],r0
	bl	dword_le_load			; *inp++
	xor	$A[0][4],$A[0][4],r0
	bl	dword_le_load			; *inp++
	xor	$A[1][0],$A[1][0],r0
	bl	dword_le_load			; *inp++
	xor	$A[1][1],$A[1][1],r0
	bl	dword_le_load			; *inp++
	xor	$A[1][2],$A[1][2],r0
	bl	dword_le_load			; *inp++
	xor	$A[1][3],$A[1][3],r0
	blt	.Lprocess_block

	bl	dword_le_load			; *inp++
	xor	$A[1][4],$A[1][4],r0
	bl	dword_le_load			; *inp++
	xor	$A[2][0],$A[2][0],r0
	bl	dword_le_load			; *inp++
	xor	$A[2][1],$A[2][1],r0
	bl	dword_le_load			; *inp++
	xor	$A[2][2],$A[2][2],r0
	beq	.Lprocess_block

	bl	dword_le_load			; *inp++
	xor	$A[2][3],$A[2][3],r0
	bl	dword_le_load			; *inp++
	xor	$A[2][4],$A[2][4],r0
	bl	dword_le_load			; *inp++
	xor	$A[3][0],$A[3][0],r0
	bl	dword_le_load			; *inp++
	xor	$A[3][1],$A[3][1],r0
	blt	cr1,.Lprocess_block

	bl	dword_le_load			; *inp++
	xor	$A[3][2],$A[3][2],r0
	beq	cr1,.Lprocess_block

	bl	dword_le_load			; *inp++
	xor	$A[3][3],$A[3][3],r0
	bl	dword_le_load			; *inp++
	xor	$A[3][4],$A[3][4],r0
	bl	dword_le_load			; *inp++
	xor	$A[4][0],$A[4][0],r0

.Lprocess_block:
	$PUSH	r3,`$LOCALS+1*$SIZE_T`($sp)	; save inp

	bl	KeccakF1600_int

	$POP	r4,`$LOCALS+4*$SIZE_T`($sp)	; pull iotas[24]
	$POP	r0,`$LOCALS+3*$SIZE_T`($sp)	; restore bsz
	$POP	r5,`$LOCALS+2*$SIZE_T`($sp)	; restore len
	$POP	r3,`$LOCALS+1*$SIZE_T`($sp)	; restore inp
	addic	r4,r4,`-8*24`			; rewind iotas
	$PUSH	r4,`$LOCALS+4*$SIZE_T`($sp)

	b	.Loop_absorb

.align	4
.Labsorbed:
	$POP	r3,`$LOCALS+0*$SIZE_T`($sp)
	std	$A[0][0],`8*0`(r3)		; return A[5][5]
	std	$A[0][1],`8*1`(r3)
	std	$A[0][2],`8*2`(r3)
	std	$A[0][3],`8*3`(r3)
	std	$A[0][4],`8*4`(r3)
	std	$A[1][0],`8*5`(r3)
	std	$A[1][1],`8*6`(r3)
	std	$A[1][2],`8*7`(r3)
	std	$A[1][3],`8*8`(r3)
	std	$A[1][4],`8*9`(r3)
	std	$A[2][0],`8*10`(r3)
	std	$A[2][1],`8*11`(r3)
	std	$A[2][2],`8*12`(r3)
	std	$A[2][3],`8*13`(r3)
	std	$A[2][4],`8*14`(r3)
	std	$A[3][0],`8*15`(r3)
	std	$A[3][1],`8*16`(r3)
	std	$A[3][2],`8*17`(r3)
	std	$A[3][3],`8*18`(r3)
	std	$A[3][4],`8*19`(r3)
	std	$A[4][0],`8*20`(r3)
	std	$A[4][1],`8*21`(r3)
	std	$A[4][2],`8*22`(r3)
	std	$A[4][3],`8*23`(r3)
	std	$A[4][4],`8*24`(r3)

	mr	r3,r5				; return value
	$POP	r0,`$FRAME+$LRSAVE`($sp)
	$POP	r14,`$FRAME-$SIZE_T*18`($sp)
	$POP	r15,`$FRAME-$SIZE_T*17`($sp)
	$POP	r16,`$FRAME-$SIZE_T*16`($sp)
	$POP	r17,`$FRAME-$SIZE_T*15`($sp)
	$POP	r18,`$FRAME-$SIZE_T*14`($sp)
	$POP	r19,`$FRAME-$SIZE_T*13`($sp)
	$POP	r20,`$FRAME-$SIZE_T*12`($sp)
	$POP	r21,`$FRAME-$SIZE_T*11`($sp)
	$POP	r22,`$FRAME-$SIZE_T*10`($sp)
	$POP	r23,`$FRAME-$SIZE_T*9`($sp)
	$POP	r24,`$FRAME-$SIZE_T*8`($sp)
	$POP	r25,`$FRAME-$SIZE_T*7`($sp)
	$POP	r26,`$FRAME-$SIZE_T*6`($sp)
	$POP	r27,`$FRAME-$SIZE_T*5`($sp)
	$POP	r28,`$FRAME-$SIZE_T*4`($sp)
	$POP	r29,`$FRAME-$SIZE_T*3`($sp)
	$POP	r30,`$FRAME-$SIZE_T*2`($sp)
	$POP	r31,`$FRAME-$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,4,1,0x80,18,4,0
	.long	0
.size	SHA3_absorb,.-SHA3_absorb
___
{
my ($A_flat,$out,$len,$bsz) = map("r$_",(28..31));
$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze,\@function
.align	5
SHA3_squeeze:
	$STU	$sp,`-10*$SIZE_T`($sp)
	mflr	r0
	$PUSH	r28,`6*$SIZE_T`($sp)
	$PUSH	r29,`7*$SIZE_T`($sp)
	$PUSH	r30,`8*$SIZE_T`($sp)
	$PUSH	r31,`9*$SIZE_T`($sp)
	$PUSH	r0,`10*$SIZE_T+$LRSAVE`($sp)

	mr	$A_flat,r3
	subi	r3,r3,8			; prepare for ldu
	subi	$out,r4,1		; prepare for stbu
	mr	$len,r5
	mr	$bsz,r6
	b	.Loop_squeeze

.align	4
.Loop_squeeze:
	ldu	r0,8(r3)
	${UCMP}i $len,8
	blt	.Lsqueeze_tail

	stb	r0,1($out)
	srdi	r0,r0,8
	stb	r0,2($out)
	srdi	r0,r0,8
	stb	r0,3($out)
	srdi	r0,r0,8
	stb	r0,4($out)
	srdi	r0,r0,8
	stb	r0,5($out)
	srdi	r0,r0,8
	stb	r0,6($out)
	srdi	r0,r0,8
	stb	r0,7($out)
	srdi	r0,r0,8
	stbu	r0,8($out)

	subic.	$len,$len,8
	beq	.Lsqueeze_done

	subic.	r6,r6,8
	bgt	.Loop_squeeze

	mr	r3,$A_flat
	bl	KeccakF1600
	subi	r3,$A_flat,8		; prepare for ldu
	mr	r6,$bsz
	b	.Loop_squeeze

.align	4
.Lsqueeze_tail:
	mtctr	$len
.Loop_tail:
	stbu	r0,1($out)
	srdi	r0,r0,8
	bdnz	.Loop_tail

.Lsqueeze_done:
	$POP	r0,`10*$SIZE_T+$LRSAVE`($sp)
	$POP	r28,`6*$SIZE_T`($sp)
	$POP	r29,`7*$SIZE_T`($sp)
	$POP	r30,`8*$SIZE_T`($sp)
	$POP	r31,`9*$SIZE_T`($sp)
	mtlr	r0
	addi	$sp,$sp,`10*$SIZE_T`
	blr
	.long	0
	.byte	0,12,4,1,0x80,4,4,0
	.long	0
.size	SHA3_squeeze,.-SHA3_squeeze
___
}

# Ugly hack here, because PPC assembler syntax seem to vary too
# much from platforms to platform...
$code.=<<___;
.align	6
PICmeup:
	mflr	r0
	bcl	20,31,\$+4
	mflr	r12   ; vvvvvv "distance" between . and 1st data entry
	addi	r12,r12,`64-8`
	mtlr	r0
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
	.space	`64-9*4`
.type	iotas,\@object
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
.asciz	"Keccak-1600 absorb and squeeze for PPC64, CRYPTOGAMS by \@dot-asm"
___
}}} else {{{
########################################################################
# 32-bit code path...
#
my @A = map([ 8*$_, 8*($_+1), 8*($_+2), 8*($_+3), 8*($_+4) ], (0,5,10,15,20));

my @C = map("r$_", (22..31));
my @D = map("r$_", (10..11,14..21));
my @T = map("r$_", (0,5..9));

$code.=<<___;
.text

.type	KeccakF1600_int,\@function
.align	5
KeccakF1600_int:
	$STU	$sp, -`$LOCALS+208`($sp)
	li	r0,24
	lwz	@D[0], $A[4][0]+0(r3)
	lwz	@D[1], $A[4][0]+4(r3)
	lwz	@D[2], $A[4][1]+0(r3)
	lwz	@D[3], $A[4][1]+4(r3)
	lwz	@D[4], $A[4][2]+0(r3)
	lwz	@D[5], $A[4][2]+4(r3)
	lwz	@D[6], $A[4][3]+0(r3)
	lwz	@D[7], $A[4][3]+4(r3)
	lwz	@D[8], $A[4][4]+0(r3)
	lwz	@D[9], $A[4][4]+4(r3)
	addi	r4, $sp, $LOCALS		# T[5][5]
	subi	r12, r12, 4			# prepare iotas for lwzu
	mtctr	r0
	b	.Loop
.align	4
.Loop:
	lwz	@C[0], $A[0][0]+0(r3)
	lwz	@C[1], $A[0][0]+4(r3)
	lwz	@C[2], $A[0][1]+0(r3)
	lwz	@C[3], $A[0][1]+4(r3)
	lwz	@C[4], $A[0][2]+0(r3)
	lwz	@C[5], $A[0][2]+4(r3)
	lwz	@C[6], $A[0][3]+0(r3)
	lwz	@C[7], $A[0][3]+4(r3)
	lwz	@C[8], $A[0][4]+0(r3)
	lwz	@C[9], $A[0][4]+4(r3)
	xor	@C[0], @C[0], @D[0]
	lwz	@D[0], $A[1][0]+0(r3)
	xor	@C[1], @C[1], @D[1]
	lwz	@D[1], $A[1][0]+4(r3)
	xor	@C[2], @C[2], @D[2]
	lwz	@D[2], $A[1][1]+0(r3)
	xor	@C[3], @C[3], @D[3]
	lwz	@D[3], $A[1][1]+4(r3)
	xor	@C[4], @C[4], @D[4]
	lwz	@D[4], $A[1][2]+0(r3)
	xor	@C[5], @C[5], @D[5]
	lwz	@D[5], $A[1][2]+4(r3)
	xor	@C[6], @C[6], @D[6]
	lwz	@D[6], $A[1][3]+0(r3)
	xor	@C[7], @C[7], @D[7]
	lwz	@D[7], $A[1][3]+4(r3)
	xor	@C[8], @C[8], @D[8]
	lwz	@D[8], $A[1][4]+0(r3)
	xor	@C[9], @C[9], @D[9]
	lwz	@D[9], $A[1][4]+4(r3)
	xor	@C[0], @C[0], @D[0]
	lwz	@D[0], $A[2][0]+0(r3)
	xor	@C[1], @C[1], @D[1]
	lwz	@D[1], $A[2][0]+4(r3)
	xor	@C[2], @C[2], @D[2]
	lwz	@D[2], $A[2][1]+0(r3)
	xor	@C[3], @C[3], @D[3]
	lwz	@D[3], $A[2][1]+4(r3)
	xor	@C[4], @C[4], @D[4]
	lwz	@D[4], $A[2][2]+0(r3)
	xor	@C[5], @C[5], @D[5]
	lwz	@D[5], $A[2][2]+4(r3)
	xor	@C[6], @C[6], @D[6]
	lwz	@D[6], $A[2][3]+0(r3)
	xor	@C[7], @C[7], @D[7]
	lwz	@D[7], $A[2][3]+4(r3)
	xor	@C[8], @C[8], @D[8]
	lwz	@D[8], $A[2][4]+0(r3)
	xor	@C[9], @C[9], @D[9]
	lwz	@D[9], $A[2][4]+4(r3)
	xor	@C[0], @C[0], @D[0]
	lwz	@D[0], $A[3][0]+0(r3)
	xor	@C[1], @C[1], @D[1]
	lwz	@D[1], $A[3][0]+4(r3)
	xor	@C[2], @C[2], @D[2]
	lwz	@D[2], $A[3][1]+0(r3)
	xor	@C[3], @C[3], @D[3]
	lwz	@D[3], $A[3][1]+4(r3)
	xor	@C[4], @C[4], @D[4]
	lwz	@D[4], $A[3][2]+0(r3)
	xor	@C[5], @C[5], @D[5]
	lwz	@D[5], $A[3][2]+4(r3)
	xor	@C[6], @C[6], @D[6]
	lwz	@D[6], $A[3][3]+0(r3)
	xor	@C[7], @C[7], @D[7]
	lwz	@D[7], $A[3][3]+4(r3)
	xor	@C[8], @C[8], @D[8]
	lwz	@D[8], $A[3][4]+0(r3)
	xor	@C[9], @C[9], @D[9]
	lwz	@D[9], $A[3][4]+4(r3)
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

	rotlwi	@D[2], @C[5], 1
	xor	@D[3], @C[4], @C[1]
	rotlwi	@D[4], @C[7], 1
	xor	@D[5], @C[6], @C[3]
	rotlwi	@D[6], @C[9], 1
	xor	@D[7], @C[8], @C[5]
	rotlwi	@D[8], @C[1], 1
	xor	@D[9], @C[0], @C[7]
	rotlwi	@D[0], @C[3], 1
	xor	@D[1], @C[2], @C[9]
	xor	@D[2], @D[2], @C[0]	; D[1] = ROL64(C[2], 1) ^ C[0];
	xor	@D[4], @D[4], @C[2]	; D[2] = ROL64(C[3], 1) ^ C[1];
	xor	@D[6], @D[6], @C[4]	; D[3] = ROL64(C[4], 1) ^ C[2];
	xor	@D[8], @D[8], @C[6]	; D[4] = ROL64(C[0], 1) ^ C[3];
	xor	@D[0], @D[0], @C[8]	; D[0] = ROL64(C[1], 1) ^ C[4];

	lwz	@C[0], $A[0][0]+0(r3)
	lwz	@C[1], $A[0][0]+4(r3)
	lwz	@C[2], $A[1][1]+0(r3)
	lwz	@C[3], $A[1][1]+4(r3)
	xor	@C[0], @C[0], @D[0]
	lwz	@C[4], $A[2][2]+4(r3)	; flipped order
	xor	@C[1], @C[1], @D[1]
	lwz	@C[5], $A[2][2]+0(r3)
	xor	@C[2], @C[2], @D[2]
	lwz	@C[6], $A[3][3]+4(r3)	; flipped order
	xor	@C[3], @C[3], @D[3]
	lwz	@C[7], $A[3][3]+0(r3)
	xor	@C[4], @C[4], @D[5]	; flipped order
	lwz	@C[8], $A[4][4]+0(r3)
	xor	@C[5], @C[5], @D[4]
	lwz	@C[9], $A[4][4]+4(r3)
	xor	@C[6], @C[6], @D[7]	; flipped order
	 lwz	@T[4], 4(r12)		; *iotas++
	xor	@C[7], @C[7], @D[6]
	 lwzu	@T[5], 8(r12)
	xor	@C[8], @C[8], @D[8]
	xor	@C[9], @C[9], @D[9]

	rotlwi	@C[2], @C[2], 22	; rhotates[1][1] == 44
	rotlwi	@C[3], @C[3], 22
	rotlwi	@C[4], @C[4], 22	; rhotates[2][2] == 43
	rotlwi	@C[5], @C[5], 21
	rotlwi	@C[6], @C[6], 11	; rhotates[3][3] == 21
	rotlwi	@C[7], @C[7], 10
	rotlwi	@C[8], @C[8], 7		; rhotates[4][4] == 14
	rotlwi	@C[9], @C[9], 7

	andc	@T[0], @C[4], @C[2]
	andc	@T[1], @C[5], @C[3]
	andc	@T[2], @C[6], @C[4]
	andc	@T[3], @C[7], @C[5]
	 xor	@T[0], @T[0], @T[4]	; ^= iotas[i]
	 xor	@T[1], @T[1], @T[5]
	andc	@T[4], @C[8], @C[6]
	andc	@T[5], @C[9], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	xor	@T[4], @T[4], @C[4]
	stw	@T[0], $A[0][0]+0(r4)	; R[0][0] = C[0] ^ (~C[1] & C[2]);
	xor	@T[5], @T[5], @C[5]
	stw	@T[1], $A[0][0]+4(r4)
	andc	@T[0], @C[0], @C[8]
	stw	@T[2], $A[0][1]+0(r4)	; R[0][1] = C[1] ^ (~C[2] & C[3]);
	andc	@T[1], @C[1], @C[9]
	stw	@T[3], $A[0][1]+4(r4)
	andc	@C[2], @C[2], @C[0]
	stw	@T[4], $A[0][2]+0(r4)	; R[0][2] = C[2] ^ (~C[3] & C[4]);
	andc	@C[3], @C[3], @C[1]
	stw	@T[5], $A[0][2]+4(r4)
	xor	@C[6], @C[6], @T[0]
	lwz	@C[0], $A[0][3]+0(r3)
	xor	@C[7], @C[7], @T[1]
	lwz	@C[1], $A[0][3]+4(r3)
	xor	@C[8], @C[8], @C[2]
	lwz	@C[2], $A[1][4]+0(r3)
	xor	@C[9], @C[9], @C[3]
	lwz	@C[3], $A[1][4]+4(r3)
	stw	@C[6], $A[0][3]+0(r4)	; R[0][3] = C[3] ^ (~C[4] & C[0]);
	stw	@C[7], $A[0][3]+4(r4)
	stw	@C[8], $A[0][4]+0(r4)	; R[0][4] = C[4] ^ (~C[0] & C[1]);
	stw	@C[9], $A[0][4]+4(r4)

	xor	@C[0], @C[0], @D[6]
	lwz	@C[4], $A[2][0]+4(r3)	; flipped order
	xor	@C[1], @C[1], @D[7]
	lwz	@C[5], $A[2][0]+0(r3)
	xor	@C[2], @C[2], @D[8]
	lwz	@C[6], $A[3][1]+4(r3)	; flipped order
	xor	@C[3], @C[3], @D[9]
	lwz	@C[7], $A[3][1]+0(r3)
	xor	@C[4], @C[4], @D[1]	; flipped order
	lwz	@C[8], $A[4][2]+4(r3)	; flipped order
	xor	@C[5], @C[5], @D[0]
	lwz	@C[9], $A[4][2]+0(r3)
	xor	@C[6], @C[6], @D[3]	; flipped order
	xor	@C[7], @C[7], @D[2]
	xor	@C[8], @C[8], @D[5]	; flipped order
	xor	@C[9], @C[9], @D[4]

	rotlwi	@C[0], @C[0], 14	; rhotates[0][3] == 28
	rotlwi	@C[1], @C[1], 14
	rotlwi	@C[2], @C[2], 10	; rhotates[1][4] == 20
	rotlwi	@C[3], @C[3], 10
	rotlwi	@C[4], @C[4], 2		; rhotates[2][0] == 3
	rotlwi	@C[5], @C[5], 1
	rotlwi	@C[6], @C[6], 23	; rhotates[3][1] == 45
	rotlwi	@C[7], @C[7], 22
	rotlwi	@C[8], @C[8], 31	; rhotates[4][2] == 61
	rotlwi	@C[9], @C[9], 30

	andc	@T[0], @C[4], @C[2]
	andc	@T[1], @C[5], @C[3]
	andc	@T[2], @C[6], @C[4]
	andc	@T[3], @C[7], @C[5]
	andc	@T[4], @C[8], @C[6]
	andc	@T[5], @C[9], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	xor	@T[4], @T[4], @C[4]
	stw	@T[0], $A[1][0]+0(r4)	; R[1][0] = C[0] ^ (~C[1] & C[2]);
	xor	@T[5], @T[5], @C[5]
	stw	@T[1], $A[1][0]+4(r4)
	andc	@T[0], @C[0], @C[8]
	stw	@T[2], $A[1][1]+0(r4)	; R[1][1] = C[1] ^ (~C[2] & C[3]);
	andc	@T[1], @C[1], @C[9]
	stw	@T[3], $A[1][1]+4(r4)
	andc	@C[2], @C[2], @C[0]
	stw	@T[4], $A[1][2]+0(r4)	; R[1][2] = C[2] ^ (~C[3] & C[4]);
	andc	@C[3], @C[3], @C[1]
	stw	@T[5], $A[1][2]+4(r4)
	xor	@C[6], @C[6], @T[0]
	lwz	@C[0], $A[0][1]+4(r3)	; flipped order
	xor	@C[7], @C[7], @T[1]
	lwz	@C[1], $A[0][1]+0(r3)
	xor	@C[8], @C[8], @C[2]
	lwz	@C[2], $A[1][2]+0(r3)
	xor	@C[9], @C[9], @C[3]
	lwz	@C[3], $A[1][2]+4(r3)
	stw	@C[6], $A[1][3]+0(r4)	; R[1][3] = C[3] ^ (~C[4] & C[0]);
	stw	@C[7], $A[1][3]+4(r4)
	stw	@C[8], $A[1][4]+0(r4)	; R[1][4] = C[4] ^ (~C[0] & C[1]);
	stw	@C[9], $A[1][4]+4(r4)

	xor	@C[0], @C[0], @D[3]	; flipped order
	lwz	@C[4], $A[2][3]+4(r3)	; flipped order
	xor	@C[1], @C[1], @D[2]
	lwz	@C[5], $A[2][3]+0(r3)
	xor	@C[2], @C[2], @D[4]
	lwz	@C[6], $A[3][4]+0(r3)
	xor	@C[3], @C[3], @D[5]
	lwz	@C[7], $A[3][4]+4(r3)
	xor	@C[4], @C[4], @D[7]	; flipped order
	lwz	@C[8], $A[4][0]+0(r3)
	xor	@C[5], @C[5], @D[6]
	lwz	@C[9], $A[4][0]+4(r3)
	xor	@C[6], @C[6], @D[8]
	xor	@C[7], @C[7], @D[9]
	xor	@C[8], @C[8], @D[0]
	xor	@C[9], @C[9], @D[1]

	rotlwi	@C[0], @C[0], 1		; rhotates[0][1] == 1
	;rotlwi	@C[1], @C[1], 0
	rotlwi	@C[2], @C[2], 3		; rhotates[1][2] == 6
	rotlwi	@C[3], @C[3], 3
	rotlwi	@C[4], @C[4], 13	; rhotates[2][3] == 25
	rotlwi	@C[5], @C[5], 12
	rotlwi	@C[6], @C[6], 4		; rhotates[3][4] == 8
	rotlwi	@C[7], @C[7], 4
	rotlwi	@C[8], @C[8], 9		; rhotates[4][0] == 18
	rotlwi	@C[9], @C[9], 9

	andc	@T[0], @C[4], @C[2]
	andc	@T[1], @C[5], @C[3]
	andc	@T[2], @C[6], @C[4]
	andc	@T[3], @C[7], @C[5]
	andc	@T[4], @C[8], @C[6]
	andc	@T[5], @C[9], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	xor	@T[4], @T[4], @C[4]
	stw	@T[0], $A[2][0]+0(r4)	; R[2][0] = C[0] ^ (~C[1] & C[2]);
	xor	@T[5], @T[5], @C[5]
	stw	@T[1], $A[2][0]+4(r4)
	andc	@T[0], @C[0], @C[8]
	stw	@T[2], $A[2][1]+0(r4)	; R[2][1] = C[1] ^ (~C[2] & C[3]);
	andc	@T[1], @C[1], @C[9]
	stw	@T[3], $A[2][1]+4(r4)
	andc	@C[2], @C[2], @C[0]
	stw	@T[4], $A[2][2]+0(r4)	; R[2][2] = C[2] ^ (~C[3] & C[4]);
	andc	@C[3], @C[3], @C[1]
	stw	@T[5], $A[2][2]+4(r4)
	xor	@C[6], @C[6], @T[0]
	lwz	@C[0], $A[0][4]+4(r3)	; flipped order
	xor	@C[7], @C[7], @T[1]
	lwz	@C[1], $A[0][4]+0(r3)
	xor	@C[8], @C[8], @C[2]
	lwz	@C[2], $A[1][0]+0(r3)
	xor	@C[9], @C[9], @C[3]
	lwz	@C[3], $A[1][0]+4(r3)
	stw	@C[6], $A[2][3]+0(r4)	; R[2][3] = C[3] ^ (~C[4] & C[0]);
	stw	@C[7], $A[2][3]+4(r4)
	stw	@C[8], $A[2][4]+0(r4)	; R[2][4] = C[4] ^ (~C[0] & C[1]);
	stw	@C[9], $A[2][4]+4(r4)

	xor	@C[0], @C[0], @D[9]	; flipped order
	lwz	@C[4], $A[2][1]+0(r3)
	xor	@C[1], @C[1], @D[8]
	lwz	@C[5], $A[2][1]+4(r3)
	xor	@C[2], @C[2], @D[0]
	lwz	@C[6], $A[3][2]+4(r3)	; flipped order
	xor	@C[3], @C[3], @D[1]
	lwz	@C[7], $A[3][2]+0(r3)
	xor	@C[4], @C[4], @D[2]
	lwz	@C[8], $A[4][3]+0(r3)
	xor	@C[5], @C[5], @D[3]
	lwz	@C[9], $A[4][3]+4(r3)
	xor	@C[6], @C[6], @D[5]	; flipped order
	xor	@C[7], @C[7], @D[4]
	xor	@C[8], @C[8], @D[6]
	xor	@C[9], @C[9], @D[7]

	rotlwi	@C[0], @C[0], 14	; rhotates[0][4] == 27
	rotlwi	@C[1], @C[1], 13
	rotlwi	@C[2], @C[2], 18	; rhotates[1][0] == 36
	rotlwi	@C[3], @C[3], 18
	rotlwi	@C[4], @C[4], 5		; rhotates[2][1] == 10
	rotlwi	@C[5], @C[5], 5
	rotlwi	@C[6], @C[6], 8		; rhotates[3][2] == 15
	rotlwi	@C[7], @C[7], 7
	rotlwi	@C[8], @C[8], 28	; rhotates[4][3] == 56
	rotlwi	@C[9], @C[9], 28

	andc	@T[0], @C[4], @C[2]
	andc	@T[1], @C[5], @C[3]
	andc	@T[2], @C[6], @C[4]
	andc	@T[3], @C[7], @C[5]
	andc	@T[4], @C[8], @C[6]
	andc	@T[5], @C[9], @C[7]
	xor	@T[0], @T[0], @C[0]
	xor	@T[1], @T[1], @C[1]
	xor	@T[2], @T[2], @C[2]
	xor	@T[3], @T[3], @C[3]
	xor	@T[4], @T[4], @C[4]
	stw	@T[0], $A[3][0]+0(r4)	; R[3][0] = C[0] ^ (~C[1] & C[2]);
	xor	@T[5], @T[5], @C[5]
	stw	@T[1], $A[3][0]+4(r4)
	andc	@T[0], @C[0], @C[8]
	stw	@T[2], $A[3][1]+0(r4)	; R[3][1] = C[1] ^ (~C[2] & C[3]);
	andc	@T[1], @C[1], @C[9]
	stw	@T[3], $A[3][1]+4(r4)
	andc	@C[2], @C[2], @C[0]
	stw	@T[4], $A[3][2]+0(r4)	; R[3][2] = C[2] ^ (~C[3] & C[4]);
	andc	@C[3], @C[3], @C[1]
	stw	@T[5], $A[3][2]+4(r4)
	xor	@C[6], @C[6], @T[0]
	lwz	@C[0], $A[0][2]+0(r3)
	xor	@C[7], @C[7], @T[1]
	lwz	@C[1], $A[0][2]+4(r3)
	xor	@C[8], @C[8], @C[2]
	lwz	@C[2], $A[1][3]+4(r3)	; flipped order
	xor	@C[9], @C[9], @C[3]
	lwz	@C[3], $A[1][3]+0(r3)
	stw	@C[6], $A[3][3]+0(r4)	; R[3][3] = C[3] ^ (~C[4] & C[0]);
	stw	@C[7], $A[3][3]+4(r4)
	stw	@C[8], $A[3][4]+0(r4)	; R[3][4] = C[4] ^ (~C[0] & C[1]);
	stw	@C[9], $A[3][4]+4(r4)
	 xor	r4, r4, r3		; xchg	r3, r4

	xor	@C[0], @C[0], @D[4]
	lwz	@C[4], $A[2][4]+4(r3)	; flipped order
	xor	@C[1], @C[1], @D[5]
	lwz	@C[5], $A[2][4]+0(r3)
	xor	@C[2], @C[2], @D[7]	; flipped order
	lwz	@C[6], $A[3][0]+4(r3)	; flipped order
	xor	@C[3], @C[3], @D[6]
	lwz	@C[7], $A[3][0]+0(r3)
	xor	@C[4], @C[4], @D[9]	; flipped order
	lwz	@C[8], $A[4][1]+0(r3)
	xor	@C[5], @C[5], @D[8]
	lwz	@C[9], $A[4][1]+4(r3)
	 xor	r3, r3, r4
	xor	@C[6], @C[6], @D[1]	; flipped order
	xor	@C[7], @C[7], @D[0]
	 xor	r4, r4, r3
	xor	@C[8], @C[8], @D[2]
	xor	@C[9], @C[9], @D[3]

	rotlwi	@C[0], @C[0], 31	; rhotates[0][2] == 62
	rotlwi	@C[1], @C[1], 31
	rotlwi	@C[2], @C[2], 28	; rhotates[1][3] == 55
	rotlwi	@C[3], @C[3], 27
	rotlwi	@C[4], @C[4], 20	; rhotates[2][4] == 39
	rotlwi	@C[5], @C[5], 19
	rotlwi	@C[6], @C[6], 21	; rhotates[3][0] == 41
	rotlwi	@C[7], @C[7], 20
	rotlwi	@C[8], @C[8], 1		; rhotates[4][1] == 2
	rotlwi	@C[9], @C[9], 1

	andc	@D[0], @C[4], @C[2]
	andc	@D[1], @C[5], @C[3]
	andc	@D[2], @C[6], @C[4]
	andc	@D[3], @C[7], @C[5]
	andc	@D[4], @C[8], @C[6]
	andc	@D[5], @C[9], @C[7]
	andc	@D[6], @C[0], @C[8]
	andc	@D[7], @C[1], @C[9]
	andc	@D[8], @C[2], @C[0]
	andc	@D[9], @C[3], @C[1]
	xor	@D[0], @D[0], @C[0]
	xor	@D[1], @D[1], @C[1]
	xor	@D[2], @D[2], @C[2]
	xor	@D[3], @D[3], @C[3]
	stw	@D[0], $A[4][0]+0(r3)	; R[4][0] = C[0] ^ (~C[1] & C[2]);
	xor	@D[4], @D[4], @C[4]
	stw	@D[1], $A[4][0]+4(r3)
	xor	@D[5], @D[5], @C[5]
	stw	@D[2], $A[4][1]+0(r3)	; R[4][1] = C[1] ^ (~C[2] & C[3]);
	xor	@D[6], @D[6], @C[6]
	stw	@D[3], $A[4][1]+4(r3)
	xor	@D[7], @D[7], @C[7]
	stw	@D[4], $A[4][2]+0(r3)	; R[4][2] = C[2] ^ (~C[3] & C[4]);
	xor	@D[8], @D[8], @C[8]
	stw	@D[5], $A[4][2]+4(r3)
	xor	@D[9], @D[9], @C[9]
	stw	@D[6], $A[4][3]+0(r3)	; R[4][3] = C[3] ^ (~C[4] & C[0]);
	stw	@D[7], $A[4][3]+4(r3)
	stw	@D[8], $A[4][4]+0(r3)	; R[4][4] = C[4] ^ (~C[0] & C[1]);
	stw	@D[9], $A[4][4]+4(r3)
	bdnz	.Loop

	addi	$sp,$sp,`$LOCALS+208`
	blr
	.long	0
	.byte	0,12,4,0,0x80,0,1,0
	.long	0
.size	KeccakF1600_int,.-KeccakF1600_int
___
{
my ($inp, $len, $bsz, $A_flat) = map("r$_",(4..7));
my ($lo, $hi) = map("r$_",(14,15));
my ($t0, $t1, $t2, $t3, $t4, $t5, $t6, $t7) = map("r$_",(16..23));
my ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7) = map("r$_",(24..31));

$code.=<<___;
.globl	SHA3_absorb
.type	SHA3_absorb,\@function
.align	5
SHA3_absorb:
	$UCMP	$len, $bsz			; len < bsz?
	blt	.Labort
	$STU	$sp, -$FRAME($sp)
	mflr	r0
	$PUSH	r14, `$FRAME-$SIZE_T*18`($sp)
	$PUSH	r15, `$FRAME-$SIZE_T*17`($sp)
	$PUSH	r16, `$FRAME-$SIZE_T*16`($sp)
	$PUSH	r17, `$FRAME-$SIZE_T*15`($sp)
	$PUSH	r18, `$FRAME-$SIZE_T*14`($sp)
	$PUSH	r19, `$FRAME-$SIZE_T*13`($sp)
	$PUSH	r20, `$FRAME-$SIZE_T*12`($sp)
	$PUSH	r21, `$FRAME-$SIZE_T*11`($sp)
	$PUSH	r22, `$FRAME-$SIZE_T*10`($sp)
	$PUSH	r23, `$FRAME-$SIZE_T*9`($sp)
	$PUSH	r24, `$FRAME-$SIZE_T*8`($sp)
	$PUSH	r25, `$FRAME-$SIZE_T*7`($sp)
	$PUSH	r26, `$FRAME-$SIZE_T*6`($sp)
	$PUSH	r27, `$FRAME-$SIZE_T*5`($sp)
	$PUSH	r28, `$FRAME-$SIZE_T*4`($sp)
	$PUSH	r29, `$FRAME-$SIZE_T*3`($sp)
	$PUSH	r30, `$FRAME-$SIZE_T*2`($sp)
	$PUSH	r31, `$FRAME-$SIZE_T*1`($sp)
	$PUSH	r0,  `$FRAME+$LRSAVE`($sp)

	bl	PICmeup

	subi	$inp, $inp, 1			; prepare for lbzu
	$PUSH	$bsz, `$LOCALS+3*$SIZE_T`($sp)
	$PUSH	r12,  `$LOCALS+4*$SIZE_T`($sp)	; save iotas

	b	.Loop_absorb

.align	4
.Loop_absorb:
	lis	$s0, 0x5555
	lis	$s1, 0x3333
	lis	$s2, 0x0f0f
	lis	$s3, 0x00ff
	ori	$s0, $s0, 0x5555		; 0x55555555
	ori	$s1, $s1, 0x3333		; 0x33333333
	ori	$s2, $s2, 0x0f0f		; 0x0f0f0f0f
	ori	$s3, $s3, 0x00ff		; 0x00ff00ff
	slwi	$s4, $s0, 1			; 0xaaaaaaaa
	slwi	$s5, $s1, 2			; 0xcccccccc
	slwi	$s6, $s2, 4			; 0xf0f0f0f0
	slwi	$s7, $s3, 8			; 0xff00ff00

	srwi	r0, $bsz, 3
	sub	$len, $len, $bsz
	subi	$A_flat, r3, 4
	mtctr	r0

.Loop_block:
	lbz	$lo, 1($inp)
	lbz	$hi, 5($inp)
	lbz	$t0, 2($inp)
	lbz	$t1, 6($inp)
	lbz	$t2, 3($inp)
	lbz	$t3, 7($inp)
	insrwi	$lo, $t0, 8, 16
	lbz	$t4, 4($inp)
	insrwi	$hi, $t1, 8, 16
	lbzu	$t5, 8($inp)
	insrwi	$lo, $t2, 8, 8
	insrwi	$hi, $t3, 8, 8
	insrwi	$lo, $t4, 8, 0
	insrwi	$hi, $t5, 8, 0

	lwz	$t6, 4($A_flat)
	lwz	$t7, 8($A_flat)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; bit interleave
	and	$t0, $lo, $s0		; t0 = lo & 0x55555555;
	 and	$t1, $hi, $s0		; t1 = hi & 0x55555555;
	  and	$lo, $lo, $s4		; lo &= 0xaaaaaaaa;
	   and	$hi, $hi, $s4		; hi &= 0xaaaaaaaa;
	srwi	$t2, $t0, 1
	 srwi	$t3, $t1, 1
	  slwi	$t4, $lo, 1
	   slwi	$t5, $hi, 1
	or	$t0, $t0, $t2		; t0 |= t0 >> 1;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 1;
	  or	$lo, $lo, $t4		; lo |= lo << 1;
	   or	$hi, $hi, $t5		; hi |= hi << 1;
	and	$t0, $t0, $s1		; t0 &= 0x33333333;
	 and	$t1, $t1, $s1		; t1 &= 0x33333333;
	  and	$lo, $lo, $s5		; lo &= 0xcccccccc;
	   and	$hi, $hi, $s5		; hi &= 0xcccccccc;
	srwi	$t2, $t0, 2
	 srwi	$t3, $t1, 2
	  slwi	$t4, $lo, 2
	   slwi	$t5, $hi, 2
	or	$t0, $t0, $t2		; t0 |= t0 >> 2;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 2;
	  or	$lo, $lo, $t4		; lo |= lo << 2;
	   or	$hi, $hi, $t5		; hi |= hi << 2;
	and	$t0, $t0, $s2		; t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s2		; t1 &= 0x0f0f0f0f;
	  and	$lo, $lo, $s6		; lo &= 0xf0f0f0f0;
	   and	$hi, $hi, $s6		; hi &= 0xf0f0f0f0;
	srwi	$t2, $t0, 4
	 srwi	$t3, $t1, 4
	  slwi	$t4, $lo, 4
	   slwi	$t5, $hi, 4
	or	$t0, $t0, $t2		; t0 |= t0 >> 4;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 4;
	  or	$lo, $lo, $t4		; lo |= lo << 4;
	   or	$hi, $hi, $t5		; hi |= hi << 4;
	and	$t0, $t0, $s3		; t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s3		; t1 &= 0x00ff00ff;
	  and	$lo, $lo, $s7		; lo &= 0xff00ff00;
	   and	$hi, $hi, $s7		; hi &= 0xff00ff00;
	srwi	$t2, $t0, 8
	 srwi	$t3, $t1, 8
	  slwi	$t4, $lo, 8
	   slwi	$t5, $hi, 8
	or	$t0, $t0, $t2		; t0 |= t0 >> 8;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 8;
	  or	$lo, $lo, $t4		; lo |= lo << 8;
	   or	$hi, $hi, $t5		; hi |= hi << 8;
	andi.	$t0, $t0, 0xffff	; t0 &= 0x0000ffff;
	 slwi	$t1, $t1, 16		; t1 <<= 16;
	  srwi	$lo, $lo, 16		; lo >>= 16;
	   andis. $hi, $hi, 0xffff	; hi &= 0xffff0000;

	xor	$t6, $t6, $t0		; absorb
	xor	$t7, $t7, $lo
	xor	$t6, $t6, $t1
	xor	$t7, $t7, $hi

	stw	$t6, 4($A_flat)
	stwu	$t7, 8($A_flat)
	bdnz	.Loop_block

	$PUSH	$len, `$LOCALS+2*$SIZE_T`($sp)	; save len
	$PUSH	$inp, `$LOCALS+1*$SIZE_T`($sp)	; save next input block

	bl	KeccakF1600_int

	$POP	$bsz, `$LOCALS+3*$SIZE_T`($sp)	; restore bsz
	$POP	$len, `$LOCALS+2*$SIZE_T`($sp)	; restore len
	$POP	$inp, `$LOCALS+1*$SIZE_T`($sp)	; restore inp
	$POP	r12,  `$LOCALS+4*$SIZE_T`($sp)	; restore iotas
	addi	$A_flat, r3, 4

	$UCMP	$len, $bsz			; len < bsz?
	bge	.Loop_absorb

	$POP	r0,  `$FRAME+$LRSAVE`($sp)
	$POP	r14, `$FRAME-$SIZE_T*18`($sp)
	$POP	r15, `$FRAME-$SIZE_T*17`($sp)
	$POP	r16, `$FRAME-$SIZE_T*16`($sp)
	$POP	r17, `$FRAME-$SIZE_T*15`($sp)
	$POP	r18, `$FRAME-$SIZE_T*14`($sp)
	$POP	r19, `$FRAME-$SIZE_T*13`($sp)
	$POP	r20, `$FRAME-$SIZE_T*12`($sp)
	$POP	r21, `$FRAME-$SIZE_T*11`($sp)
	$POP	r22, `$FRAME-$SIZE_T*10`($sp)
	$POP	r23, `$FRAME-$SIZE_T*9`($sp)
	$POP	r24, `$FRAME-$SIZE_T*8`($sp)
	$POP	r25, `$FRAME-$SIZE_T*7`($sp)
	$POP	r26, `$FRAME-$SIZE_T*6`($sp)
	$POP	r27, `$FRAME-$SIZE_T*5`($sp)
	$POP	r28, `$FRAME-$SIZE_T*4`($sp)
	$POP	r29, `$FRAME-$SIZE_T*3`($sp)
	$POP	r30, `$FRAME-$SIZE_T*2`($sp)
	$POP	r31, `$FRAME-$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,$FRAME
.Labort:
	mr	r3, $len				; return value
	blr
	.long	0
	.byte	0,12,4,1,0x80,18,4,0
	.long	0
.size	SHA3_absorb,.-SHA3_absorb
___

my $out = $inp;

$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze,\@function
.align	5
SHA3_squeeze:
	$STU	$sp, -$FRAME($sp)
	mflr	r0
	$PUSH	r14, `$FRAME-$SIZE_T*18`($sp)
	$PUSH	r15, `$FRAME-$SIZE_T*17`($sp)
	$PUSH	r16, `$FRAME-$SIZE_T*16`($sp)
	$PUSH	r17, `$FRAME-$SIZE_T*15`($sp)
	$PUSH	r18, `$FRAME-$SIZE_T*14`($sp)
	$PUSH	r19, `$FRAME-$SIZE_T*13`($sp)
	$PUSH	r20, `$FRAME-$SIZE_T*12`($sp)
	$PUSH	r21, `$FRAME-$SIZE_T*11`($sp)
	$PUSH	r22, `$FRAME-$SIZE_T*10`($sp)
	$PUSH	r23, `$FRAME-$SIZE_T*9`($sp)
	$PUSH	r24, `$FRAME-$SIZE_T*8`($sp)
	$PUSH	r25, `$FRAME-$SIZE_T*7`($sp)
	$PUSH	r26, `$FRAME-$SIZE_T*6`($sp)
	$PUSH	r27, `$FRAME-$SIZE_T*5`($sp)
	$PUSH	r28, `$FRAME-$SIZE_T*4`($sp)
	$PUSH	r29, `$FRAME-$SIZE_T*3`($sp)
	$PUSH	r30, `$FRAME-$SIZE_T*2`($sp)
	$PUSH	r31, `$FRAME-$SIZE_T*1`($sp)
	$PUSH	r0,  `$FRAME+$LRSAVE`($sp)

	bl	PICmeup

	subi	$out, $out, 1			; prepare for lbzu
	$PUSH	$bsz, `$LOCALS+3*$SIZE_T`($sp)	; save bsz
	$PUSH	r12,  `$LOCALS+4*$SIZE_T`($sp)	; save iotas

	b	.Lsqueeze_entry

.align	4
.Loop_squeeze:
	lwz	$lo, 4($A_flat)
	lwzu	$hi, 8($A_flat)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; bit deinterleave
	andi.	$t0, $lo, 0xffff	; t0 = lo & 0x0000ffff;
	 slwi	$t1, $hi, 16		; t1 = hi << 16;
	  srwi	$lo, $lo, 16		; lo >>= 16;
	   andis. $hi, $hi, 0xffff	; hi &= 0xffff0000;
	slwi	$t2, $t0, 8
	 srwi	$t3, $t1, 8
	  slwi	$t4, $lo, 8
	   srwi	$t5, $hi, 8
	or	$t0, $t0, $t2		; t0 |= t0 << 8;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 1;
	  or	$lo, $lo, $t4		; lo |= lo << 8;
	   or	$hi, $hi, $t5		; hi |= hi >> 8;
	and	$t0, $t0, $s3		; t0 &= 0x00ff00ff;
	 and	$t1, $t1, $s7		; t1 &= 0xff00ff00;
	  and	$lo, $lo, $s3		; lo &= 0x00ff00ff;
	   and	$hi, $hi, $s7		; hi &= 0xff00ff00;
	slwi	$t2, $t0, 4
	 srwi	$t3, $t1, 4
	  slwi	$t4, $lo, 4
	   srwi	$t5, $hi, 4
	or	$t0, $t0, $t2		; t0 |= t0 << 4;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 2;
	  or	$lo, $lo, $t4		; lo |= lo << 4;
	   or	$hi, $hi, $t5		; hi |= hi >> 4;
	and	$t0, $t0, $s2		; t0 &= 0x0f0f0f0f;
	 and	$t1, $t1, $s6		; t1 &= 0xf0f0f0f0;
	  and	$lo, $lo, $s2		; lo &= 0x0f0f0f0f;
	   and	$hi, $hi, $s6		; hi &= 0xf0f0f0f0;
	slwi	$t2, $t0, 2
	 srwi	$t3, $t1, 2
	  slwi	$t4, $lo, 2
	   srwi	$t5, $hi, 2
	or	$t0, $t0, $t2		; t0 |= t0 << 2;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 4;
	  or	$lo, $lo, $t4		; lo |= lo << 2;
	   or	$hi, $hi, $t5		; hi |= hi >> 2;
	and	$t0, $t0, $s1		; t0 &= 0x33333333;
	 and	$t1, $t1, $s5		; t1 &= 0xcccccccc;
	  and	$lo, $lo, $s1		; lo &= 0x33333333;
	   and	$hi, $hi, $s5		; hi &= 0xcccccccc;
	slwi	$t2, $t0, 1
	 srwi	$t3, $t1, 1
	  slwi	$t4, $lo, 1
	   srwi	$t5, $hi, 1
	or	$t0, $t0, $t2		; t0 |= t0 >> 8;
	 or	$t1, $t1, $t3		; t1 |= t1 >> 8;
	  or	$lo, $lo, $t4		; lo |= lo << 1;
	   or	$hi, $hi, $t5		; hi |= hi >> 1;
	and	$t0, $t0, $s0		; t0 &= 0x55555555;
	 and	$t1, $t1, $s4		; t1 &= 0xaaaaaaaa;
	  and	$lo, $lo, $s0		; lo &= 0x55555555;
	   and	$hi, $hi, $s4		; hi &= 0xaaaaaaaa;

	or	$hi, $hi, $lo
	or	$lo, $t0, $t1

	cmplwi	$len,4
	blt	.Lsqueeze_tail

	srwi	$t0, $lo, 8
	stb	$lo, 1($out)
	srwi	$t1, $lo, 16
	stb	$t0, 2($out)
	srwi	$t2, $lo, 24
	stb	$t1, 3($out)
	subic.	$len, $len, 4
	stbu	$t2, 4($out)
	beq	.Lsqueeze_done
	mr	$lo, $hi
	cmplwi	$len, 4
	blt	.Lsqueeze_tail

	srwi	$t0, $lo, 8
	stb	$lo, 1($out)
	srwi	$t1, $lo, 16
	stb	$t0, 2($out)
	srwi	$t2, $lo, 24
	stb	$t1, 3($out)
	subic.	$len, $len, 4
	stbu	$t2, 4($out)
	beq	.Lsqueeze_done

	subic.	$bsz, $bsz, 8
	bgt	.Loop_squeeze

	$PUSH	$len, `$LOCALS+2*$SIZE_T`($sp)
	$PUSH	$out, `$LOCALS+1*$SIZE_T`($sp)

	bl	KeccakF1600_int

	$POP	r12,  `$LOCALS+4*$SIZE_T`($sp)	; pop iotas
	$POP	$bsz, `$LOCALS+3*$SIZE_T`($sp)
	$POP	$len, `$LOCALS+2*$SIZE_T`($sp)
	$POP	$out, `$LOCALS+1*$SIZE_T`($sp)

.Lsqueeze_entry:
	lis	$s0, 0x5555
	lis	$s1, 0x3333
	lis	$s2, 0x0f0f
	lis	$s3, 0x00ff
	ori	$s0, $s0, 0x5555	; 0x55555555
	ori	$s1, $s1, 0x3333	; 0x33333333
	ori	$s2, $s2, 0x0f0f	; 0x0f0f0f0f
	ori	$s3, $s3, 0x00ff	; 0x00ff00ff
	slwi	$s4, $s0, 1		; 0xaaaaaaaa
	slwi	$s5, $s1, 2		; 0xcccccccc
	slwi	$s6, $s2, 4		; 0xf0f0f0f0
	slwi	$s7, $s3, 8		; 0xff00ff00
	subi	$A_flat, r3, 4		; prepare for lwzu
	b	.Loop_squeeze

.align	4
.Lsqueeze_tail:
	mtctr	$len
.Loop_tail:
	stbu	$lo, 1($out)
	srwi	$lo, $lo, 8
	bdnz	.Loop_tail

.Lsqueeze_done:
	$POP	r0,  `$FRAME+$LRSAVE`($sp)
	$POP	r14, `$FRAME-$SIZE_T*18`($sp)
	$POP	r15, `$FRAME-$SIZE_T*17`($sp)
	$POP	r16, `$FRAME-$SIZE_T*16`($sp)
	$POP	r17, `$FRAME-$SIZE_T*15`($sp)
	$POP	r18, `$FRAME-$SIZE_T*14`($sp)
	$POP	r19, `$FRAME-$SIZE_T*13`($sp)
	$POP	r20, `$FRAME-$SIZE_T*12`($sp)
	$POP	r21, `$FRAME-$SIZE_T*11`($sp)
	$POP	r22, `$FRAME-$SIZE_T*10`($sp)
	$POP	r23, `$FRAME-$SIZE_T*9`($sp)
	$POP	r24, `$FRAME-$SIZE_T*8`($sp)
	$POP	r25, `$FRAME-$SIZE_T*7`($sp)
	$POP	r26, `$FRAME-$SIZE_T*6`($sp)
	$POP	r27, `$FRAME-$SIZE_T*5`($sp)
	$POP	r28, `$FRAME-$SIZE_T*4`($sp)
	$POP	r29, `$FRAME-$SIZE_T*3`($sp)
	$POP	r30, `$FRAME-$SIZE_T*2`($sp)
	$POP	r31, `$FRAME-$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,4,1,0x80,18,4,0
	.long	0
.size	SHA3_squeeze,.-SHA3_squeeze
___
}

# Ugly hack here, because PPC assembler syntax seem to vary too
# much from platforms to platform...
$code.=<<___;
.align	6
PICmeup:
	mflr	r0
	bcl	20,31,\$+4
	mflr	r12   ; vvvvvv "distance" between . and 1st data entry
	addi	r12,r12,`64-8`
	mtlr	r0
	blr
	.long	0
	.byte	0,12,0x14,0,0,0,0,0
	.space	`64-9*4`
.type	iotas,\@object
iotas:
	.long	0x00000001, 0x00000000
	.long	0x00000000, 0x00000089
	.long	0x00000000, 0x8000008b
	.long	0x00000000, 0x80008080
	.long	0x00000001, 0x0000008b
	.long	0x00000001, 0x00008000
	.long	0x00000001, 0x80008088
	.long	0x00000001, 0x80000082
	.long	0x00000000, 0x0000000b
	.long	0x00000000, 0x0000000a
	.long	0x00000001, 0x00008082
	.long	0x00000000, 0x00008003
	.long	0x00000001, 0x0000808b
	.long	0x00000001, 0x8000000b
	.long	0x00000001, 0x8000008a
	.long	0x00000001, 0x80000081
	.long	0x00000000, 0x80000081
	.long	0x00000000, 0x80000008
	.long	0x00000000, 0x00000083
	.long	0x00000000, 0x80008003
	.long	0x00000001, 0x80008088
	.long	0x00000000, 0x80000088
	.long	0x00000001, 0x00008000
	.long	0x00000000, 0x80008082
.size	iotas,.-iotas
.asciz	"Keccak-1600 absorb and squeeze for PPC, CRYPTOGAMS by \@dot-asm"
___
}}}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
