#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is dual licensed under OpenSSL and CRYPTOGAMS
# licenses depending on where you obtain it. For further details see
# https://github.com/dot-asm/cryptogams/.
# ====================================================================
#
# Keccak-1600 for Itanium.
#
# November 2018.
#
# Straightforward KECCAK_1X variant with A[][], T[][], C[] and D[]
# held in registers, 45 in total. Pre-9000 Itanium 2 achieves 6.8
# cycles per processed byte in SHA3-256 benchmark; 9xxx processors -
# 5.2, best result for a pure software implementation so far.

$output = pop;
open STDOUT, ">$output" if $output;

{{{

my @D = map("r$_",(10,11,14,15,16));
my @C = map("r$_",(17..21));
my @T = map([ "r$_", "r".($_+1), "r".($_+2), "r".($_+3), "r".($_+4) ],
            (22, 27));
my @A = map([ "r$_", "r".($_-1), "r".($_-2), "r".($_-3), "r".($_-4) ],
            (56, 51, 46, 41, 36));

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

$code.=<<___;
#if defined(_HPUX_SOURCE)
# if !defined(_LP64)
#  define ADDP	addp4
# else
#  define ADDP	add
# endif
# define RUM	rum
# define SUM	sum
#else
# define ADDP	add
# define RUM	nop
# define SUM	nop
#endif

.text
.explicit

.align	64
.type	iotas#,\@object
iotas:
	data1	0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x82,0x80,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x8a,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x00,0x80,0x00,0x80,0x00,0x00,0x00,0x80
	data1	0x8b,0x80,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x01,0x00,0x00,0x80,0x00,0x00,0x00,0x00
	data1	0x81,0x80,0x00,0x80,0x00,0x00,0x00,0x80
	data1	0x09,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x8a,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x88,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x09,0x80,0x00,0x80,0x00,0x00,0x00,0x00
	data1	0x0a,0x00,0x00,0x80,0x00,0x00,0x00,0x00
	data1	0x8b,0x80,0x00,0x80,0x00,0x00,0x00,0x00
	data1	0x8b,0x00,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x89,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x03,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x02,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x0a,0x80,0x00,0x00,0x00,0x00,0x00,0x00
	data1	0x0a,0x00,0x00,0x80,0x00,0x00,0x00,0x80
	data1	0x81,0x80,0x00,0x80,0x00,0x00,0x00,0x80
	data1	0x80,0x80,0x00,0x00,0x00,0x00,0x00,0x80
	data1	0x01,0x00,0x00,0x80,0x00,0x00,0x00,0x00
	data1	0x08,0x80,0x00,0x80,0x00,0x00,0x00,0x80
.size	iotas#,192

.proc	KeccakF1600_b6#
KeccakF1600_b6:
	.prologue
	.altrp	b6
	.body
{ .mib;	mov	r9=ip
	brp.loop.imp	.Lctop,.Lcend-16	};;
{ .mii;	adds	r9=-192,r9				// iotas
	mov	ar.lc=23
	mov	ar.ec=1				};;
.Lctop:
{ .mmi;	xor	$C[0]=$A[0][0],$A[1][0]
	xor	$C[1]=$A[0][1],$A[1][1]
	xor	$C[2]=$A[0][2],$A[1][2]		}
{ .mmi;	xor	$C[3]=$A[0][3],$A[1][3]
	xor	$C[4]=$A[0][4],$A[1][4]

	xor	$D[0]=$A[2][0],$A[3][0]		};;
{ .mmi;	xor	$C[0]=$C[0],$A[4][0]
	xor	$D[1]=$A[2][1],$A[3][1]
	xor	$C[1]=$C[1],$A[4][1]		}
{ .mmi;	xor	$D[2]=$A[2][2],$A[3][2]
	xor	$C[2]=$C[2],$A[4][2]
	xor	$D[3]=$A[2][3],$A[3][3]		};;
{ .mmi;	xor	$C[3]=$C[3],$A[4][3]
	xor	$C[4]=$C[4],$A[4][4]
	xor	$D[4]=$A[2][4],$A[3][4]		}

{ .mmi;	xor	$C[0]=$C[0],$D[0]
	xor	$C[1]=$C[1],$D[1]
	xor	$C[2]=$C[2],$D[2]		};;
{ .mmi;	xor	$C[3]=$C[3],$D[3]
	xor	$C[4]=$C[4],$D[4]
	rol	$D[0]=$C[1],1			};;

{ .mii;	xor	$D[0]=$D[0],$C[4]
	rol	$D[1]=$C[2],1
	rol	$D[2]=$C[3],1			};;
{ .mmi;	xor	$D[1]=$D[1],$C[0]
	xor	$D[2]=$D[2],$C[1]
	rol	$D[4]=$C[0],1			}
{ .mmi;	xor	$T[0][0]=$A[3][0],$D[0]			// borrow T[0][0]
	xor	$C[0]=$A[0][0],$D[0]
	rol	$D[3]=$C[4],1			};;

{ .mmi;	xor	$D[3]=$D[3],$C[2]
	xor	$D[4]=$D[4],$C[3]
	xor	$C[1]=$A[1][1],$D[1]		}
{ .mmi;	xor	$C[2]=$A[2][2],$D[2]

	xor	$T[0][1]=$A[0][1],$D[1]
	xor	$T[0][2]=$A[0][2],$D[2]		};;
{ .mmi;	xor	$T[0][3]=$A[0][3],$D[3]
	xor	$T[0][4]=$A[0][4],$D[4]
	rol	$C[1]=$C[1],$rhotates[1][1]	}

{ .mmi;	xor	$C[3]=$A[3][3],$D[3]
	xor	$C[4]=$A[4][4],$D[4]
	rol	$C[2]=$C[2],$rhotates[2][2]	};;

{ .mmi;	xor	$T[1][0]=$A[1][0],$D[0]
	xor	$T[1][1]=$A[2][1],$D[1]			// borrow T[1][1]
	rol	$C[3]=$C[3],$rhotates[3][3]	}
{ .mmi;	xor	$T[1][2]=$A[1][2],$D[2]
	xor	$T[1][3]=$A[1][3],$D[3]
	rol	$C[4]=$C[4],$rhotates[4][4]	};;

{ .mmi;	andcm	$A[0][0]=$C[2],$C[1]
	andcm	$A[0][1]=$C[3],$C[2]
	andcm	$A[0][2]=$C[4],$C[3]		}
{ .mmi;	andcm	$A[0][3]=$C[0],$C[4]
	andcm	$A[0][4]=$C[1],$C[0]
	xor	$T[1][4]=$A[2][4],$D[4]		};;	// borrow T[1][4]
{ .mmi;	xor	$A[0][0]=$A[0][0],$C[0]
	xor	$A[0][1]=$A[0][1],$C[1]
	rol	$C[0]=$T[0][3],$rhotates[0][3]	}
{ .mmi;	xor	$C[1]=$A[1][4],$D[4]
	xor	$A[0][2]=$A[0][2],$C[2]
	xor	$C[2]=$A[2][0],$D[0]		};;
{ .mmi;	xor	$A[0][3]=$A[0][3],$C[3]
	xor	$C[3]=$A[3][1],$D[1]
	rol	$C[1]=$C[1],   $rhotates[1][4]	}
{ .mmi;	xor	$A[0][4]=$A[0][4],$C[4]
	xor	$C[4]=$A[4][2],$D[2]
	rol	$C[2]=$C[2],   $rhotates[2][0]	};;

{ .mmi;	andcm	$A[1][0]=$C[2],$C[1]
	andcm	$A[1][4]=$C[1],$C[0]
	rol	$C[3]=$C[3],   $rhotates[3][1]	}
{ .mmi;	xor	$T[0][3]=$A[2][3],$D[3]
	rol	$C[4]=$C[4],   $rhotates[4][2]	};;

{ .mmi;	xor	$A[1][0]=$A[1][0],$C[0]
	andcm	$A[1][3]=$C[0],$C[4]
	rol	$C[0]=$T[0][1],$rhotates[0][1]	}
{ .mmi;	andcm	$A[1][1]=$C[3],$C[2]
	andcm	$A[1][2]=$C[4],$C[3]
	xor	$A[1][4]=$A[1][4],$C[4]		};;

{ .mmi;	xor	$A[1][1]=$A[1][1],$C[1]
	xor	$A[1][2]=$A[1][2],$C[2]
	rol	$C[1]=$T[1][2],$rhotates[1][2]	}
{ .mmi;	xor	$A[1][3]=$A[1][3],$C[3]
	xor	$C[3]=$A[3][4],$D[4]
	rol	$C[2]=$T[0][3],$rhotates[2][3]	};;
{ .mmi;	andcm	$A[2][0]=$C[2],$C[1]
	xor	$C[4]=$A[4][0],$D[0]
	rol	$C[3]=$C[3],   $rhotates[3][4]	};;
{ .mmi;	ld8	$D[0]=[r9],8				// iotas[i++]
	xor	$A[2][0]=$A[2][0],$C[0]
	rol	$C[4]=$C[4],   $rhotates[4][0]	}
{ .mmi;	xor	$T[0][3]=$A[3][2],$D[2]
	xor	$T[1][2]=$A[4][3],$D[3]
	andcm	$A[2][4]=$C[1],$C[0]		};;

{ .mmi;	andcm	$A[2][1]=$C[3],$C[2]
	andcm	$A[2][3]=$C[0],$C[4]
	rol	$C[0]=$T[0][4],$rhotates[0][4]	}
{ .mmi;	andcm	$A[2][2]=$C[4],$C[3];;
	xor	$A[2][1]=$A[2][1],$C[1]
	rol	$C[1]=$T[1][0],$rhotates[1][0]	}
{ .mmi;	xor	$A[2][2]=$A[2][2],$C[2]
	xor	$A[2][3]=$A[2][3],$C[3]
	rol	$C[2]=$T[1][1],$rhotates[2][1]	};;	// originally A[2][1]
{ .mmi;	xor	$A[2][4]=$A[2][4],$C[4]

	andcm	$A[3][0]=$C[2],$C[1]
	rol	$C[3]=$T[0][3],$rhotates[3][2]	}
{ .mmi;	xor	$T[0][1]=$A[4][1],$D[1]
	andcm	$A[3][4]=$C[1],$C[0]
	rol	$C[4]=$T[1][2],$rhotates[4][3]	};;

{ .mmi;	andcm	$A[3][1]=$C[3],$C[2]
	andcm	$A[3][2]=$C[4],$C[3]
	andcm	$A[3][3]=$C[0],$C[4]		};;
{ .mmi;	xor	$A[3][0]=$A[3][0],$C[0]
	xor	$A[3][1]=$A[3][1],$C[1]
	rol	$C[0]=$T[0][2],$rhotates[0][2]	}
{ .mmi;	xor	$A[3][2]=$A[3][2],$C[2]
	xor	$A[3][3]=$A[3][3],$C[3]
	rol	$C[1]=$T[1][3],$rhotates[1][3]	};;
{ .mmi;	xor	$A[3][4]=$A[3][4],$C[4]
	andcm	$A[4][4]=$C[1],$C[0]

	rol	$C[2]=$T[1][4],$rhotates[2][4]	}	// originally A[2][4]
{ .mmi;	xor	$A[0][0]=$A[0][0],$D[0]			// A[0][0] ^= iota
	rol	$C[3]=$T[0][0],$rhotates[3][0]	};;	// originally A[3][0]

{ .mmi;	andcm	$A[4][0]=$C[2],$C[1]
	andcm	$A[4][1]=$C[3],$C[2]
	rol	$C[4]=$T[0][1],$rhotates[4][1]	};;
{ .mmi;	andcm	$A[4][2]=$C[4],$C[3]
	andcm	$A[4][3]=$C[0],$C[4]		}
{ .mmi;	xor	$A[4][4]=$A[4][4],$C[4]
	xor	$A[4][0]=$A[4][0],$C[0]
	xor	$A[4][1]=$A[4][1],$C[1]		};;
{ .mib;	xor	$A[4][2]=$A[4][2],$C[2]
	xor	$A[4][3]=$A[4][3],$C[3]
	br.ctop.sptk.many	.Lctop		};;
.Lcend:

{ .mib;	br.ret.sptk.few		b6		};;
.endp	KeccakF1600_b6#
___
}}}
$code.=<<___;
#if 0
.proc	KeccakF1600#
.align	64
KeccakF1600:
	.prologue
	.save	ar.pfs,r2
{ .mii;	alloc	r2=ar.pfs,1,0,25,0
	.save	ar.lc,r3
	mov	r3=ar.lc			}

	.body
{ .mmb;	ADDP	r30=0,in0
	ADDP	r31=8,in0			};;
{ .mmi;	ld8	out24=[r30],16				// load A[][]
	ld8	out23=[r31],16			};;
{ .mmi;	ld8	out22=[r30],16
	ld8	out21=[r31],16			};;
{ .mmi;	ld8	out20=[r30],16
	ld8	out19=[r31],16			};;
{ .mmi;	ld8	out18=[r30],16
	ld8	out17=[r31],16			};;
{ .mmi;	ld8	out16=[r30],16
	ld8	out15=[r31],16			};;
{ .mmi;	ld8	out14=[r30],16
	ld8	out13=[r31],16			};;
{ .mmi;	ld8	out12=[r30],16
	ld8	out11=[r31],16			};;
{ .mmi;	ld8	out10=[r30],16
	ld8	out9=[r31],16			};;
{ .mmi;	ld8	out8=[r30],16
	ld8	out7=[r31],16			};;
{ .mmi;	ld8	out6=[r30],16
	ld8	out5=[r31],16			};;
{ .mmi;	ld8	out4=[r30],16
	ld8	out3=[r31],16			};;
{ .mmi;	ld8	out2=[r30],16
	ld8	out1=[r31],16			};;
{ .mmb;	ld8	out0=[r30],16
	RUM	1<<1					// go little-endian
	br.call.sptk.many	b6=KeccakF1600_b6 };;

{ .mmi;	SUM	1<<1					// back to big-endian
	ADDP	r30=0,in0
	ADDP	r31=8,in0			};;
{ .mmi;	st8	[r30]=out24,16  			// store A[][]
	st8	[r31]=out23,16  		};;
{ .mmi;	st8	[r30]=out22,16
	st8	[r31]=out21,16  		};;
{ .mmi;	st8	[r30]=out20,16
	st8	[r31]=out19,16  		};;
{ .mmi;	st8	[r30]=out18,16
	st8	[r31]=out17,16  		};;
{ .mmi;	st8	[r30]=out16,16
	st8	[r31]=out15,16  		};;
{ .mmi;	st8	[r30]=out14,16
	st8	[r31]=out13,16  		};;
{ .mmi;	st8	[r30]=out12,16
	st8	[r31]=out11,16  		};;
{ .mmi;	st8	[r30]=out10,16
	st8	[r31]=out9,16			};;
{ .mmi;	st8	[r30]=out8,16
	st8	[r31]=out7,16			};;
{ .mmi;	st8	[r30]=out6,16
	st8	[r31]=out5,16			};;
{ .mmi;	st8	[r30]=out4,16
	st8	[r31]=out3,16			};;
{ .mmi;	st8	[r30]=out2,16
	st8	[r31]=out1,16
	mov	ar.pfs=r2			};;
{ .mib;	st8	[r30]=out0,16
	mov	ar.lc=r3
	br.ret.sptk.many	b0		};;
.endp	KeccakF1600#
#endif

.global	SHA3_absorb#
.proc	SHA3_absorb#
.align	64
SHA3_absorb:
	.prologue
	.save	ar.pfs,r2
{ .mii;	alloc	r2=ar.pfs,4,3,25,32
	.save	pr,r3
	mov	r3=pr
	.save	ar.lc,loc1
	mov	loc1=ar.lc			};;

	.body
	len=in2;
	bsz=in3;

{ .mib;	cmp.ltu	p6,p0=len,bsz				// len < bsz
	mov	r8=len					// return len
(p6)	br.ret.spnt.many	b0		};;	// nothing to do

	.body
{ .mmi;	ADDP	r30=0,in0
	ADDP	r31=8,in0
	shr.u	loc0=bsz,3			};;	// bsz/8
{ .mmi;	ld8	out24=[r30],16				// load A[][]
	ld8	out23=[r31],16
	sub	loc0=loc0,r0,1			};;	// loop counter
{ .mmi;	ld8	out22=[r30],16
	ld8	out21=[r31],16
	ADDP	in1=0,in1			};;
{ .mmi;	ld8	out20=[r30],16
	ld8	out19=[r31],16
	and	r8=7,in1			};;
{ .mmi;	ld8	out18=[r30],16
	ld8	out17=[r31],16
	and	in1=~7,in1			};;	// align inp
{ .mmi;	ld8	out16=[r30],16
	ld8	out15=[r31],16
	cmp.eq	p9,p0=0,r8			};;
{ .mmi;	ld8	out14=[r30],16
	ld8	out13=[r31],16
	cmp.eq	p10,p0=7,r8			};;
{ .mmi;	ld8	out12=[r30],16
	ld8	out11=[r31],16
	cmp.eq	p11,p0=6,r8			};;
{ .mmi;	ld8	out10=[r30],16
	ld8	out9=[r31],16
	cmp.eq	p12,p0=5,r8			};;
{ .mmi;	ld8	out8=[r30],16
	ld8	out7=[r31],16
	cmp.eq	p13,p0=4,r8			};;
{ .mmi;	ld8	out6=[r30],16
	ld8	out5=[r31],16
	cmp.eq	p14,p0=3,r8			};;
{ .mmi;	ld8	out4=[r30],16
	ld8	out3=[r31],16
	cmp.eq	p15,p0=2,r8			};;
{ .mmi;	ld8	out2=[r30],16
	ld8	out1=[r31],16			};;
{ .mmb;	ld8	out0=[r30],16
	RUM	1<<1					// go little-endian
(p9)	br.cond.dptk		.Loop_0		}	// loop per alignment
{ .bbb;
(p10)	br.cond.dpnt		.Loop_7
(p11)	br.cond.dpnt		.Loop_6
(p12)	br.cond.dpnt		.Loop_5		}
{ .bbb;
(p13)	br.cond.dpnt		.Loop_4
(p14)	br.cond.dpnt		.Loop_3
(p15)	br.cond.dpnt		.Loop_2		};;
___
sub loop {
my $align = shift;
$code.=<<___;
.align	32
.Loop_$align:
{ .mib;	ld8	r8=[in1]
	mov	pr.rot=1<<16
	brp.loop.imp	.Lctop_$align,.Lcend_$align-16	}
{ .mii;	add	r31=8,in1				// copy inp+8
	mov	ar.lc=loc0
	mov	ar.ec=2				};;

.Lctop_$align:
{ .mii;	(p17)	shrp	r10=r9,r8,8*$align
	(p17)	mov	r8=r9			}
{ .mmi;	(p16)	ld8	r9=[r31],8;;
	(p17)	xor	r32=r32,r10		}
{ .mib;	br.ctop.sptk	.Lctop_$align		};;
.Lcend_$align:

{ .mib;	clrrrb					};;
{ .mib;	add	in1=in1,bsz				// inp += bsz
	sub	len=len,bsz				// len -= bsz
	br.call.sptk.many	b6=KeccakF1600_b6 };;

{ .mbb;	cmp.ltu	p6,p7=len,bsz
(p7)	br.cond.dptk	.Loop_$align
(p6)	br.cond.dpnt	.Ldone_absorb		};;
___
}
	&loop(1);
	&loop(2);
	&loop(3);
	&loop(4);
	&loop(5);
	&loop(6);
	&loop(7);
$code.=<<___;
.align	32
.Loop_0:
{ .mib;	mov	r31=in1					// copy inp
	mov	pr.rot=1<<16
	brp.loop.imp	.Lctop_0,.Lctop		}
{ .mii;	mov	ar.lc=loc0
	mov	ar.ec=2				};;
.Lctop_0:
{ .mmb;	(p17)	xor	r32=r32,r8
	(p16)	ld8	r8=[r31],8
	br.ctop.sptk	.Lctop_0		};;

{ .mib;	clrrrb					};;
{ .mib;	add	in1=in1,bsz				// inp += bsz
	sub	len=len,bsz				// len -= bsz
	br.call.sptk.many	b6=KeccakF1600_b6 };;

{ .mib;	cmp.ltu	p6,p7=len,bsz
(p7)	br.cond.dptk	.Loop_0			};;

.Ldone_absorb:
{ .mmi;	SUM	1<<1					// back to big-endian
	ADDP	r30=0,in0
	ADDP	r31=8,in0			};;
{ .mmi;	st8	[r30]=out24,16				// store A[][]
	st8	[r31]=out23,16
	mov	r8=len				};;	// return len
{ .mmi;	st8	[r30]=out22,16
	st8	[r31]=out21,16			};;
{ .mmi;	st8	[r30]=out20,16
	st8	[r31]=out19,16			};;
{ .mmi;	st8	[r30]=out18,16
	st8	[r31]=out17,16			};;
{ .mmi;	st8	[r30]=out16,16
	st8	[r31]=out15,16			};;
{ .mmi;	st8	[r30]=out14,16
	st8	[r31]=out13,16			};;
{ .mmi;	st8	[r30]=out12,16
	st8	[r31]=out11,16			};;
{ .mmi;	st8	[r30]=out10,16
	st8	[r31]=out9,16			};;
{ .mmi;	st8	[r30]=out8,16
	st8	[r31]=out7,16			};;
{ .mmi;	st8	[r30]=out6,16
	st8	[r31]=out5,16
	mov	ar.pfs=r2			};;
{ .mmi;	st8	[r30]=out4,16
	st8	[r31]=out3,16
	mov	pr=r3,0x1ffff			};;
{ .mmi;	st8	[r30]=out2,16
	st8	[r31]=out1,16
	mov	ar.lc=loc1			};;
{ .mib;	st8	[r30]=out0,16
	br.ret.sptk.many	b0		};;
.endp	SHA3_absorb#

.global	SHA3_squeeze#
.proc	SHA3_squeeze#
.align	64
SHA3_squeeze:
	.prologue
	.save	ar.pfs,r2
{ .mii;	alloc	r2=ar.pfs,4,3,25,32
	.save	pr,r3
	mov	r3=pr
	.save	ar.lc,loc1
	mov	loc1=ar.lc			};;

	.body
	len=in2;
	bsz=in3;

{ .mmi;	ADDP	r30=0,in0
	ADDP	r31=8,in0
	ADDP	r8=0,in1			};;
{ .mmi;	ld8	out24=[r30],16				// load A[][]
	ld8	out23=[r31],16			};;
{ .mmi;	ld8	out22=[r30],16
	ld8	out21=[r31],16			};;
{ .mmi;	ld8	out20=[r30],16
	ld8	out19=[r31],16			};;
{ .mmi;	ld8	out18=[r30],16
	ld8	out17=[r31],16			};;
{ .mmi;	ld8	out16=[r30],16
	ld8	out15=[r31],16			};;
{ .mmi;	ld8	out14=[r30],16
	ld8	out13=[r31],16			};;
{ .mmi;	ld8	out12=[r30],16
	ld8	out11=[r31],16			};;
{ .mmi;	ld8	out10=[r30],16
	ld8	out9=[r31],16			};;
{ .mmi;	ld8	out8=[r30],16
	ld8	out7=[r31],16			};;
{ .mmi;	ld8	out6=[r30],16
	ld8	out5=[r31],16			};;
{ .mmi;	ld8	out4=[r30],16
	ld8	out3=[r31],16			};;
{ .mmi;	ld8	out2=[r30],16
	ld8	out1=[r31],16			};;
{ .mib;	ld8	out0=[r30],16			};;

.Loop_squeeze:
{ .mmi;	cmp.leu	p14,p15=len,bsz;;			// len <= bsz
(p14)	mov	r9=len
(p15)	mov	r9=bsz				};;
{ .mmi;	cmp.leu	p7,p6=8,r9				// 8 <= min(len,bsz)
	sub	len=len,r9				// len -= min(len,bsz)
	shr.u	r10=r9,3			};;
{ .mbb;	sub	r10=r10,r0,1				// loop counter
	brp.loop.imp	.Lctop_squeeze,.Lcend_squeeze-16
(p6)	br.cond.spnt	.Lshort			};;
{ .mii;	mov	ar.lc=r10
	mov	ar.ec=1				};;

.Lctop_squeeze:
{ .mmi;	(p0)	st1	[r8]=r63,1			// smash complete words
	(p0)	shr.u	r30=r63,8		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,16		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,24		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,32		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,40		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,48		};;
{ .mmi;	(p0)	st1	[r8]=r30,1
	(p0)	shr.u	r30=r63,56		};;
{ .mmb;	(p0)	st1	[r8]=r30,1
	(p0)	add	r9=-8,r9			// min(len,bsz) -= 8
	br.ctop.sptk	.Lctop_squeeze		};;
.Lcend_squeeze:

{ .mib;	cmp.eq	p6,p0=0,r9
(p6)	br.cond.sptk	.Lno_short		};;

.Lshort:
{ .mmi;	(p0)	st1	[r8]=r63,1			// smash partial word
		cmp.ltu	p6,p0=1,r9
		shr.u	r30=r63,8		};;
{ .mmi;	(p6)	st1	[r8]=r30,1
		cmp.ltu	p6,p0=2,r9
		shr.u	r30=r63,16		};;
{ .mmi;	(p6)	st1	[r8]=r30,1
		cmp.ltu	p6,p0=3,r9
		shr.u	r30=r63,24		};;
{ .mmi;	(p6)	st1	[r8]=r30,1
		cmp.ltu	p6,p0=4,r9
		shr.u	r30=r63,32		};;
{ .mmi;	(p6)	st1	[r8]=r30,1
		cmp.ltu	p6,p0=5,r9
		shr.u	r30=r63,40		};;
{ .mmi;	(p6)	st1	[r8]=r30,1
		cmp.ltu	p6,p0=6,r9
		shr.u	r30=r63,48		};;
{ .mmi;	(p6)	st1	[r8]=r30,1		};;

.Lno_short:
{ .mib;	clrrrb					};;
{ .mbb;
(p15)	RUM	1<<1					// go little-endian
(p15)	br.call.dpnt.many	b6=KeccakF1600_b6
(p14)	br.cond.dptk.few	.Ldone_squeeze	};;
{ .mib;	SUM	1<<1					// back to big-endian
	br.many			.Loop_squeeze	};;

.Ldone_squeeze:
{ .mii;	mov	ar.pfs=r2
	mov	pr=r3,0x1ffff			};;
{ .mib;	mov	ar.lc=loc1
	br.ret.sptk.many	b0		};;
.endp	SHA3_squeeze#
stringz	"Keccak-1600 absorb and squeeze for IA64, CRYPTOGAMS by \@dot-asm"
___

foreach(split("\n",$code)) {

    s/rol(\s+)(r[0-9]+)=(r[0-9]+),\s*([0-9]+)/shrp$1$2=$3,$3,64-$4/g;

    print $_,"\n";
}

close STDOUT;
