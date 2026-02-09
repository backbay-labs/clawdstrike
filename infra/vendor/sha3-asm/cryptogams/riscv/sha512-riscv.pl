#!/usr/bin/env perl
#
# SHA2 block procedures for RISC-V.
#
# February 2024.
#
# This is transliteration of the corresponding MIPS module. Just like
# the original SHA512 is supported only in 64-bit build. U74 spends
# 36.5/25.0 cycles per one byte processed with SHA256/SHA512, C910 -
# 27.3/18.0, JH7110 (U74+zbb) - 21.3/14.9.
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

$flavour = shift;
if ($flavour=~/\w[\w\-]*\.\w+$/) { $output=$flavour; undef $flavour; }
for (@ARGV) { $output=$_ if (/\w[\w\-]*\.\w+$/); }
open STDOUT,">$output";

if ($output =~ /512/) {
	$label="512";
	$SZ=8;
	$LD="ld";		# load from memory
	$ST="sd";		# store to memory
	$SLL="sll";		# shift left logical
	$SRL="srl";		# shift right logical
	$ROTR="ror";
	@Sigma0=(28,34,39);
	@Sigma1=(14,18,41);
	@sigma0=( 7, 1, 8);	# right shift first
	@sigma1=( 6,19,61);	# right shift first
	$lastK=0x017;
	$rounds=80;
} else {
	$label="256";
	$SZ=4;
	$LD="lw";		# load from memory
	$ST="sw";		# store to memory
	$SLL="sllw";		# shift left logical
	$SRL="srlw";		# shift right logical
	$ROTR="rorw";
	@Sigma0=( 2,13,22);
	@Sigma1=( 6,11,25);
	@sigma0=( 3, 7,18);	# right shift first
	@sigma1=(10,17,19);	# right shift first
	$lastK=0x0f2;
	$rounds=64;
}

$code.=<<___;
#if __riscv_xlen == 32
# if __SIZEOF_POINTER__ == 8
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sw
#  define POP	lw
# endif
# define sllw	sll
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
#define FRAMESIZE		(16*$SZ+16*__SIZEOF_POINTER__)
___

@V=($A,$B,$C,$D,$E,$F,$G,$H)=map("x$_",(5..9,13..15));
@X=map("x$_",(16..31));

$ctx=$a0;
$inp=$a1;
$len=$a2;	$Ktbl=$len;

sub BODY_00_15 {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;
my ($T1,$tmp0,$tmp1,$tmp2)=(@X[4],@X[5],@X[6],@X[7]);

$code.=<<___	if ($i<15 && $SZ==4);
	lbu	@X[1],`($i+1)*$SZ+0`($inp)
	lbu	$tmp0,`($i+1)*$SZ+1`($inp)
	lbu	$tmp1,`($i+1)*$SZ+2`($inp)
	sll	@X[1],@X[1],24
	lbu	$tmp2,`($i+1)*$SZ+3`($inp)
	sll	$tmp0,$tmp0,16
	or	@X[1],@X[1],$tmp0
	sll	$tmp1,$tmp1,8
	or	@X[1],@X[1],$tmp1
	or	@X[1],@X[1],$tmp2
___
$code.=<<___	if ($i<15 && $SZ==8);
	lbu	@X[1],`($i+1)*$SZ+0`($inp)
	lbu	$tmp0,`($i+1)*$SZ+1`($inp)
	lbu	$tmp1,`($i+1)*$SZ+2`($inp)
	sll	@X[1],@X[1],56
	lbu	$tmp2,`($i+1)*$SZ+3`($inp)
	sll	$tmp0,$tmp0,48
	or	@X[1],@X[1],$tmp0
	lbu	$tmp0,`($i+1)*$SZ+4`($inp)
	sll	$tmp1,$tmp1,40
	or	@X[1],@X[1],$tmp1
	lbu	$tmp1,`($i+1)*$SZ+5`($inp)
	sll	$tmp2,$tmp2,32
	or	@X[1],@X[1],$tmp2
	lbu	$tmp2,`($i+1)*$SZ+6`($inp)
	sll	$tmp0,$tmp0,24
	or	@X[1],@X[1],$tmp0
	lbu	$tmp0,`($i+1)*$SZ+7`($inp)
	sll	$tmp1,$tmp1,16
	or	@X[1],@X[1],$tmp1
	sll	$tmp2,$tmp2,8
	or	@X[1],@X[1],$tmp2
	or	@X[1],@X[1],$tmp0
___
$code.=<<___;
#ifdef	__riscv_zbb
	xor	$tmp2,$f,$g			# $i
	$ROTR	$tmp0,$e,@Sigma1[0]
	add	$T1,$X[0],$h
	$ROTR	$tmp1,$e,@Sigma1[1]
	and	$tmp2,$tmp2,$e
	$ROTR	$h,$e,@Sigma1[2]
	xor	$tmp0,$tmp0,$tmp1
	$ROTR	$tmp1,$a,@Sigma0[0]
	xor	$tmp2,$tmp2,$g			# Ch(e,f,g)
	xor	$tmp0,$tmp0,$h			# Sigma1(e)

	$ROTR	$h,$a,@Sigma0[1]
	add	$T1,$T1,$tmp2
	$LD	$tmp2,`$i*$SZ`($Ktbl)		# K[$i]
	xor	$h,$h,$tmp1
	$ROTR	$tmp1,$a,@Sigma0[2]
	add	$T1,$T1,$tmp0
	and	$tmp0,$b,$c
	xor	$h,$h,$tmp1			# Sigma0(a)
	xor	$tmp1,$b,$c
#else
	add	$T1,$X[0],$h			# $i
	$SRL	$h,$e,@Sigma1[0]
	xor	$tmp2,$f,$g
	$SLL	$tmp1,$e,`$SZ*8-@Sigma1[2]`
	and	$tmp2,$tmp2,$e
	$SRL	$tmp0,$e,@Sigma1[1]
	xor	$h,$h,$tmp1
	$SLL	$tmp1,$e,`$SZ*8-@Sigma1[1]`
	xor	$h,$h,$tmp0
	$SRL	$tmp0,$e,@Sigma1[2]
	xor	$h,$h,$tmp1
	$SLL	$tmp1,$e,`$SZ*8-@Sigma1[0]`
	xor	$h,$h,$tmp0
	xor	$tmp2,$tmp2,$g			# Ch(e,f,g)
	xor	$tmp0,$tmp1,$h			# Sigma1(e)

	$SRL	$h,$a,@Sigma0[0]
	add	$T1,$T1,$tmp2
	$LD	$tmp2,`$i*$SZ`($Ktbl)		# K[$i]
	$SLL	$tmp1,$a,`$SZ*8-@Sigma0[2]`
	add	$T1,$T1,$tmp0
	$SRL	$tmp0,$a,@Sigma0[1]
	xor	$h,$h,$tmp1
	$SLL	$tmp1,$a,`$SZ*8-@Sigma0[1]`
	xor	$h,$h,$tmp0
	$SRL	$tmp0,$a,@Sigma0[2]
	xor	$h,$h,$tmp1
	$SLL	$tmp1,$a,`$SZ*8-@Sigma0[0]`
	xor	$h,$h,$tmp0
	and	$tmp0,$b,$c
	xor	$h,$h,$tmp1			# Sigma0(a)
	xor	$tmp1,$b,$c
#endif
	$ST	@X[0],`($i%16)*$SZ`($sp)	# offload to ring buffer
	add	$h,$h,$tmp0
	and	$tmp1,$tmp1,$a
	add	$T1,$T1,$tmp2			# +=K[$i]
	add	$h,$h,$tmp1			# +=Maj(a,b,c)
	add	$d,$d,$T1
	add	$h,$h,$T1
___
$code.=<<___ if ($i>=13);
	$LD	@X[3],`(($i+3)%16)*$SZ`($sp)	# prefetch from ring buffer
___
}

sub BODY_16_XX {
my $i=@_[0];
my ($tmp0,$tmp1,$tmp2,$tmp3)=(@X[4],@X[5],@X[6],@X[7]);

$code.=<<___;
#ifdef	__riscv_zbb
	$SRL	$tmp2,@X[1],@sigma0[0]		# Xupdate($i)
	$ROTR	$tmp0,@X[1],@sigma0[1]
	add	@X[0],@X[0],@X[9]		# +=X[i+9]
	xor	$tmp2,$tmp2,$tmp0
	$ROTR	$tmp0,@X[1],@sigma0[2]

	$SRL	$tmp3,@X[14],@sigma1[0]
	$ROTR	$tmp1,@X[14],@sigma1[1]
	xor	$tmp2,$tmp2,$tmp0		# sigma0(X[i+1])
	$ROTR	$tmp0,@X[14],@sigma1[2]
	xor	$tmp3,$tmp3,$tmp1
	add	@X[0],@X[0],$tmp2
#else
	$SRL	$tmp2,@X[1],@sigma0[0]		# Xupdate($i)
	add	@X[0],@X[0],@X[9]		# +=X[i+9]
	$SLL	$tmp1,@X[1],`$SZ*8-@sigma0[2]`
	$SRL	$tmp0,@X[1],@sigma0[1]
	xor	$tmp2,$tmp2,$tmp1
	$SLL	$tmp1,$tmp1,`@sigma0[2]-@sigma0[1]`
	xor	$tmp2,$tmp2,$tmp0
	$SRL	$tmp0,@X[1],@sigma0[2]
	xor	$tmp2,$tmp2,$tmp1

	$SRL	$tmp3,@X[14],@sigma1[0]
	xor	$tmp2,$tmp2,$tmp0		# sigma0(X[i+1])
	$SLL	$tmp1,@X[14],`$SZ*8-@sigma1[2]`
	add	@X[0],@X[0],$tmp2
	$SRL	$tmp0,@X[14],@sigma1[1]
	xor	$tmp3,$tmp3,$tmp1
	$SLL	$tmp1,$tmp1,`@sigma1[2]-@sigma1[1]`
	xor	$tmp3,$tmp3,$tmp0
	$SRL	$tmp0,@X[14],@sigma1[2]
	xor	$tmp3,$tmp3,$tmp1
#endif
	xor	$tmp3,$tmp3,$tmp0		# sigma1(X[i+14])
	add	@X[0],@X[0],$tmp3
___
	&BODY_00_15(@_);
}

$code.=<<___;
.text
.option	pic

.globl	sha${label}_block_data_order
.type	sha${label}_block_data_order,\@function
sha${label}_block_data_order:
	caddi	$sp,$sp,-FRAMESIZE
	PUSH	$s0,FRAMESIZE-1*__SIZEOF_POINTER__($sp)
	PUSH	$s1,FRAMESIZE-2*__SIZEOF_POINTER__($sp)
	PUSH	$s2,FRAMESIZE-3*__SIZEOF_POINTER__($sp)
	PUSH	$s3,FRAMESIZE-4*__SIZEOF_POINTER__($sp)
	PUSH	$s4,FRAMESIZE-5*__SIZEOF_POINTER__($sp)
	PUSH	$s5,FRAMESIZE-6*__SIZEOF_POINTER__($sp)
	PUSH	$s6,FRAMESIZE-7*__SIZEOF_POINTER__($sp)
	PUSH	$s7,FRAMESIZE-8*__SIZEOF_POINTER__($sp)
	PUSH	$s8,FRAMESIZE-9*__SIZEOF_POINTER__($sp)
	PUSH	$s9,FRAMESIZE-10*__SIZEOF_POINTER__($sp)
	PUSH	$s10,FRAMESIZE-11*__SIZEOF_POINTER__($sp)
	PUSH	$s11,FRAMESIZE-12*__SIZEOF_POINTER__($sp)

	$LD	$A,0*$SZ($ctx)		# load context
	$LD	$B,1*$SZ($ctx)
	$LD	$C,2*$SZ($ctx)
	$LD	$D,3*$SZ($ctx)
	$LD	$E,4*$SZ($ctx)
	$LD	$F,5*$SZ($ctx)
	$LD	$G,6*$SZ($ctx)
	$LD	$H,7*$SZ($ctx)

	sll	@X[15],$len,`log(16*$SZ)/log(2)`
	cllc	$Ktbl,K${label}
	cadd	@X[15],$inp,@X[15]	# pointer to the end of input
	PUSH	@X[15],16*$SZ($sp)

.Loop:
___
$code.=<<___	if ($SZ==4);
	lbu	@X[0],0($inp)
	lbu	@X[1],1($inp)
	lbu	@X[2],2($inp)
	sll	@X[0],@X[0],24
	lbu	@X[3],3($inp)
	sll	@X[1],@X[1],16
	or	@X[0],@X[0],@X[1]
	sll	@X[2],@X[2],8
	or	@X[0],@X[0],@X[2]
	or	@X[0],@X[0],@X[3]
___
$code.=<<___	if ($SZ==8);
	lbu	@X[0],0($inp)
	lbu	@X[1],1($inp)
	lbu	@X[2],2($inp)
	lbu	@X[3],3($inp)
	sll	@X[0],@X[0],56
	lbu	@X[4],4($inp)
	sll	@X[1],@X[1],48
	or	@X[0],@X[0],@X[1]
	lbu	@X[5],5($inp)
	sll	@X[2],@X[2],40
	or	@X[0],@X[0],@X[2]
	lbu	@X[6],6($inp)
	sll	@X[3],@X[3],32
	or	@X[0],@X[0],@X[3]
	lbu	@X[7],7($inp)
	sll	@X[4],@X[4],24
	or	@X[0],@X[0],@X[4]
	sll	@X[5],@X[5],16
	or	@X[0],@X[0],@X[5]
	sll	@X[6],@X[6],8
	or	@X[0],@X[0],@X[6]
	or	@X[0],@X[0],@X[7]
___
for ($i=0;$i<16;$i++)
{ &BODY_00_15($i,@V); unshift(@V,pop(@V)); push(@X,shift(@X)); }
$code.=<<___;
.L16_xx:
___
for (;$i<32;$i++)
{ &BODY_16_XX($i,@V); unshift(@V,pop(@V)); push(@X,shift(@X)); }
$code.=<<___;
	andi	@X[6],@X[6],0x7ff
	li	@X[7],$lastK
	caddi	$Ktbl,$Ktbl,16*$SZ	# Ktbl+=16
	bne	@X[6],@X[7],.L16_xx

	POP	@X[15],16*$SZ($sp)	# restore pointer to the end of input
	$LD	@X[0],0*$SZ($ctx)
	$LD	@X[1],1*$SZ($ctx)
	$LD	@X[2],2*$SZ($ctx)
	cadd	$inp,$inp,16*$SZ
	$LD	@X[3],3*$SZ($ctx)
	add	$A,$A,@X[0]
	$LD	@X[4],4*$SZ($ctx)
	add	$B,$B,@X[1]
	$LD	@X[5],5*$SZ($ctx)
	add	$C,$C,@X[2]
	$LD	@X[6],6*$SZ($ctx)
	add	$D,$D,@X[3]
	$LD	@X[7],7*$SZ($ctx)
	add	$E,$E,@X[4]
	$ST	$A,0*$SZ($ctx)
	add	$F,$F,@X[5]
	$ST	$B,1*$SZ($ctx)
	add	$G,$G,@X[6]
	$ST	$C,2*$SZ($ctx)
	add	$H,$H,@X[7]
	$ST	$D,3*$SZ($ctx)
	$ST	$E,4*$SZ($ctx)
	$ST	$F,5*$SZ($ctx)
	$ST	$G,6*$SZ($ctx)
	$ST	$H,7*$SZ($ctx)

	caddi	$Ktbl,$Ktbl,`-($rounds-16)*$SZ`	# rewind $Ktbl
	beq	$inp,@X[15],.Loop_break
	j	.Loop
.Loop_break:

	POP	$s0,FRAMESIZE-1*__SIZEOF_POINTER__($sp)
	POP	$s1,FRAMESIZE-2*__SIZEOF_POINTER__($sp)
	POP	$s2,FRAMESIZE-3*__SIZEOF_POINTER__($sp)
	POP	$s3,FRAMESIZE-4*__SIZEOF_POINTER__($sp)
	POP	$s4,FRAMESIZE-5*__SIZEOF_POINTER__($sp)
	POP	$s5,FRAMESIZE-6*__SIZEOF_POINTER__($sp)
	POP	$s6,FRAMESIZE-7*__SIZEOF_POINTER__($sp)
	POP	$s7,FRAMESIZE-8*__SIZEOF_POINTER__($sp)
	POP	$s8,FRAMESIZE-9*__SIZEOF_POINTER__($sp)
	POP	$s9,FRAMESIZE-10*__SIZEOF_POINTER__($sp)
	POP	$s10,FRAMESIZE-11*__SIZEOF_POINTER__($sp)
	POP	$s11,FRAMESIZE-12*__SIZEOF_POINTER__($sp)
	caddi	$sp,$sp,FRAMESIZE
	ret
.size	sha${label}_block_data_order,.-sha${label}_block_data_order

.section	.rodata
.align	5
K${label}:
___
if ($SZ==4) {
$code.=<<___;
	.word	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.word	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	.word	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.word	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.word	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.word	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.word	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.word	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.word	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.word	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.word	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	.word	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.word	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.word	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	.word	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.word	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
___
} else {
$code.=<<___;
	.dword	0x428a2f98d728ae22, 0x7137449123ef65cd
	.dword	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	.dword	0x3956c25bf348b538, 0x59f111f1b605d019
	.dword	0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	.dword	0xd807aa98a3030242, 0x12835b0145706fbe
	.dword	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	.dword	0x72be5d74f27b896f, 0x80deb1fe3b1696b1
	.dword	0x9bdc06a725c71235, 0xc19bf174cf692694
	.dword	0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	.dword	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	.dword	0x2de92c6f592b0275, 0x4a7484aa6ea6e483
	.dword	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	.dword	0x983e5152ee66dfab, 0xa831c66d2db43210
	.dword	0xb00327c898fb213f, 0xbf597fc7beef0ee4
	.dword	0xc6e00bf33da88fc2, 0xd5a79147930aa725
	.dword	0x06ca6351e003826f, 0x142929670a0e6e70
	.dword	0x27b70a8546d22ffc, 0x2e1b21385c26c926
	.dword	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	.dword	0x650a73548baf63de, 0x766a0abb3c77b2a8
	.dword	0x81c2c92e47edaee6, 0x92722c851482353b
	.dword	0xa2bfe8a14cf10364, 0xa81a664bbc423001
	.dword	0xc24b8b70d0f89791, 0xc76c51a30654be30
	.dword	0xd192e819d6ef5218, 0xd69906245565a910
	.dword	0xf40e35855771202a, 0x106aa07032bbd1b8
	.dword	0x19a4c116b8d2d0c8, 0x1e376c085141ab53
	.dword	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	.dword	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	.dword	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	.dword	0x748f82ee5defb2fc, 0x78a5636f43172f60
	.dword	0x84c87814a1f0ab72, 0x8cc702081a6439ec
	.dword	0x90befffa23631e28, 0xa4506cebde82bde9
	.dword	0xbef9a3f7b2c67915, 0xc67178f2e372532b
	.dword	0xca273eceea26619c, 0xd186b8c721c0c207
	.dword	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	.dword	0x06f067aa72176fba, 0x0a637dc5a2c898a6
	.dword	0x113f9804bef90dae, 0x1b710b35131c471b
	.dword	0x28db77f523047d84, 0x32caab7b40c72493
	.dword	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	.dword	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	.dword	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
___
}
$code.=<<___;
.string	"SHA${label} for RISC-V, CRYPTOGAMS by \@dot-asm"
.align	5
___

foreach (split("\n", $code)) {
    s/\`([^\`]*)\`/eval $1/ge;

    if ($flavour =~ /^cheri/) {
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
