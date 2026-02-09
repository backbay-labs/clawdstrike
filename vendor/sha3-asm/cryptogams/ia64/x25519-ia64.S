// ====================================================================
// Written by Andy Polyakov, @dot-asm.
// ====================================================================
//
// X25519 lower-level primitives for Itanium.
//
// These are base 2^51 multiplication and squaring. ~2.5x improvement
// over compiler-generated code was reported.

#if defined(_HPUX_SOURCE) && !defined(_LP64)
#define ADDP    addp4
#else
#define ADDP    add
#endif

.text
.explicit

g0=f32;	g1=f33;	g2=f34;	g3=f35;	g4=f36;
f_i=f37;	f_j=f38;	f_k=f39;

h4h=f40;	h4l=f41;
h3h=f42;	h3l=f43;
h2h=f44;	h2l=f45;
h1h=f46;	h1l=f47;
h0h=f48;	h0l=f49;
_19=f50;

H4l=r32;	H4h=r14;
H3l=r33;	H3h=r15;
H2l=r34;	H2h=r16;
H1l=r35;	H1h=r17;
H0l=r36;	H0h=r18;
mask51=r31;

.global	x25519_fe51_sqr#
.proc	x25519_fe51_sqr#
.align	64
x25519_fe51_sqr:
	.prologue
	.save		ar.pfs,r2
{ .mmi;	alloc		r2=ar.pfs,2,3,0,0
	mov		r3=19
	ADDP		r8=32,in0		}
{ .mmb;	ADDP		r9=0,in1
	ADDP		r10=32,in1
	br.many		.Lmul_entry		};;
.endp	x25519_fe51_sqr#

.global	x25519_fe51_mul#
.proc	x25519_fe51_mul#
.align	32
x25519_fe51_mul:
	.prologue
	.save		ar.pfs,r2
{ .mmi;	alloc		r2=ar.pfs,3,2,0,0
	mov		r3=19
	ADDP		r8=32,in0		}
{ .mmi;	ADDP		r9=0,in1
	ADDP		r10=32,in2		};;

	.body
.Lmul_entry:
{ .mmi;	ldf8		f_i=[r9],8
	ldf8		g4=[r10],-8		};;
{ .mmi;	setf.sig	_19=r3
	ldf8		g3=[r10],-8		};;
{ .mmi;	ldf8		g2=[r10],-8;;
	ldf8		g1=[r10],-8		};;
{ .mmi;	ldf8		g0=[r10]
	ldf8		f_j=[r9],8
	mov		mask51=-1		};;

{ .mfi;	xma.hu		h4h=g4,f_i,f0		}
{ .mfi;	xma.lu		h4l=g4,f_i,f0		}
{ .mfi;	ldf8		f_k=[r9],8
	xmpy.lu		g4=g4,_19
	shr.u		mask51=mask51,13	}
{ .mfi;	xma.hu		h3h=g3,f_i,f0		}
{ .mfi;	xma.lu		h3l=g3,f_i,f0		}
{ .mfi;	xma.hu		h2h=g2,f_i,f0		}
{ .mfi;	xma.lu		h2l=g2,f_i,f0		}
{ .mfi;	xma.hu		h1h=g1,f_i,f0		}
{ .mfi;	xma.lu		h1l=g1,f_i,f0		}
{ .mfi;	xma.hu		h0h=g0,f_i,f0		}
{ .mfi;	xma.lu		h0l=g0,f_i,f0		};;

{ .mfi;	getf.sig	H4h=h4h
	xma.hu		h4h=g3,f_j,h4l		}
{ .mfi;	xma.lu		h4l=g3,f_j,h4l		}
{ .mfi;	ldf8		f_i=[r9],8
	xmpy.lu		g3=g3,_19		}
{ .mfi;	getf.sig	H3h=h3h
	xma.hu		h3h=g2,f_j,h3l		}
{ .mfi;	xma.lu		h3l=g2,f_j,h3l		}
{ .mfi;	getf.sig	H2h=h2h
	xma.hu		h2h=g1,f_j,h2l		}
{ .mfi;	xma.lu		h2l=g1,f_j,h2l		}
{ .mfi;	getf.sig	H1h=h1h
	xma.hu		h1h=g0,f_j,h1l		}
{ .mfi;	xma.lu		h1l=g0,f_j,h1l		}
{ .mfi;	getf.sig	H0h=h0h
	xma.hu		h0h=g4,f_j,h0l		}
{ .mfi;	xma.lu		h0l=g4,f_j,h0l		};;

{ .mfi;	getf.sig	r19=h4h
	xma.hu		h4h=g2,f_k,h4l		}
{ .mfi;	xma.lu		h4l=g2,f_k,h4l		}
{ .mfi;	ldf8		f_j=[r9],8
	xmpy.lu		g2=g2,_19		}
{ .mfi;	getf.sig	r20=h3h
	xma.hu		h3h=g1,f_k,h3l		}
{ .mfi;	xma.lu		h3l=g1,f_k,h3l		}
{ .mfi;	getf.sig	r21=h2h
	xma.hu		h2h=g0,f_k,h2l		}
{ .mfi;	xma.lu		h2l=g0,f_k,h2l		}
{ .mfi;	getf.sig	r22=h1h
	xma.hu		h1h=g4,f_k,h1l		}
{ .mfi;	xma.lu		h1l=g4,f_k,h1l		}
{ .mfi;	getf.sig	r23=h0h
	xma.hu		h0h=g3,f_k,h0l		}
{ .mfi;	xma.lu		h0l=g3,f_k,h0l		};;

{ .mfi;	getf.sig	r24=h4h
	xma.hu		h4h=g1,f_i,h4l		}
{ .mfi;	xma.lu		h4l=g1,f_i,h4l		}
{ .mfi;	xmpy.lu		g1=g1,_19		}
{ .mfi;	getf.sig	r25=h3h
	xma.hu		h3h=g0,f_i,h3l		}
{ .mfi;	xma.lu		h3l=g0,f_i,h3l		}
{ .mfi;	getf.sig	r26=h2h
	xma.hu		h2h=g4,f_i,h2l		}
{ .mfi;	xma.lu		h2l=g4,f_i,h2l		}
{ .mfi;	getf.sig	r27=h1h
	xma.hu		h1h=g3,f_i,h1l		}
{ .mfi;	xma.lu		h1l=g3,f_i,h1l		}
{ .mfi;	getf.sig	r28=h0h
	xma.hu		h0h=g2,f_i,h0l		}
{ .mfi;	xma.lu		h0l=g2,f_i,h0l

	add		H4h=H4h,r19		};;
{ .mfi;	getf.sig	r19=h4h
	xma.hu		h4h=g0,f_j,h4l		}
{ .mfi;	xma.lu		h4l=g0,f_j,h4l
	add		H3h=H3h,r20		}
{ .mfi;	getf.sig	r20=h3h
	xma.hu		h3h=g4,f_j,h3l		}
{ .mfi;	xma.lu		h3l=g4,f_j,h3l
	add		H2h=H2h,r21		}
{ .mfi;	getf.sig	r21=h2h
	xma.hu		h2h=g3,f_j,h2l		}
{ .mfi;	xma.lu		h2l=g3,f_j,h2l
	add		H1h=H1h,r22		}
{ .mfi;	getf.sig	r22=h1h
	xma.hu		h1h=g2,f_j,h1l		}
{ .mfi;	xma.lu		h1l=g2,f_j,h1l
	add		H0h=H0h,r23		}
{ .mfi;	getf.sig	r23=h0h
	xma.hu		h0h=g1,f_j,h0l		}
{ .mfi;	xma.lu		h0l=g1,f_j,h0l

	add		H4h=H4h,r24		};;
{ .mmi;	getf.sig	r24=h4h
	getf.sig	H4l=h4l
	add		H3h=H3h,r25		}
{ .mmi;	getf.sig	r25=h3h
	getf.sig	H3l=h3l
	add		H2h=H2h,r26		}
{ .mmi;	getf.sig	r26=h2h
	getf.sig	H2l=h2l
	add		H1h=H1h,r27		}
{ .mmi;	getf.sig	r27=h1h
	getf.sig	H1l=h1l
	add		H0h=H0h,r28		}
{ .mmi;	getf.sig	r28=h0h
	getf.sig	H0l=h0l

	add		H4h=H4h,r19		};;
{ .mmi;	add		H3h=H3h,r20
	add		H2h=H2h,r21
	add		H1h=H1h,r22		}
{ .mmi;	add		H0h=H0h,r23;;

	add		H4h=H4h,r24
	add		H3h=H3h,r25		}
{ .mmi;	add		H2h=H2h,r26
	add		H1h=H1h,r27
	add		H0h=H0h,r28		};;

.Lreduction:
{ .mii;	rum		1<<5
	shrp		r19=H2h,H2l,51
	shrp		r20=H0h,H0l,51		}
{ .mmb;	and		H2l=H2l,mask51
	and		H0l=H0l,mask51		};;
{ .mii;	add		H3l=H3l,r19
	add		H1l=H1l,r20;;
	cmp.ltu		p6,p0=H3l,r19		}
{ .mmi;	cmp.ltu		p7,p0=H1l,r20;;
(p6)	add		H3h=H3h,r0,1
(p7)	add		H1h=H1h,r0,1		};;

{ .mii;	shrp		r21=H3h,H3l,51
	shrp		r22=H1h,H1l,51		}
{ .mmb;	and		H3l=H3l,mask51
	and		H1l=H1l,mask51		};;
{ .mii;	add		H4l=H4l,r21
	add		H2l=H2l,r22;;
	cmp.ltu		p8,p0=H4l,r21		};;
{ .mmi;
(p8)	add		H4h=H4h,r0,1;;

	shrp		r23=H4h,H4l,51		}
{ .mmi;	and		H4l=H4l,mask51;;
	shladd		r24=r23,3,r23			// r24 = 8*r23 + r23
	shr.u		r25=H2l,51		};;
{ .mmi;	shladd		r24=r24,1,r23;;			// r24 = 2*9*r23 + r23
	add		H0l=H0l,r24
	add		r9=-32,r8		};;

{ .mii;	and		H2l=H2l,mask51
	shr.u		r26=H0l,51
	and		H0l=H0l,mask51		};;
{ .mmi;	st8		[r8]=H4l,-8
	add		H3l=H3l,r25
	add		H1l=H1l,r26		};;

{ .mmi;	st8		[r8]=H3l,-8;;
	st8		[r8]=H2l,-8		};;
{ .mmb;	st8		[r8]=H1l
	st8		[r9]=H0l
	br.ret.sptk.few	b0			};;
.endp	x25519_fe51_mul#

.global	x25519_fe51_mul121666#
.proc	x25519_fe51_mul121666#
.align	32
x25519_fe51_mul121666:
	.prologue
	.save		ar.pfs,r2
{ .mmi;	alloc		r2=ar.pfs,2,3,0,0
	mov		r3=121666
	ADDP		r9=32,in1		};;

	.body
{ .mmi;	setf.sig	f_i=r3
	ldf8		g4=[r9],-8
	mov		mask51=-1		};;
{ .mmi;	ldf8		g3=[r9],-8;;
	ldf8		g2=[r9],-8
	shr.u		mask51=mask51,13	};;
{ .mmi;	ldf8		g1=[r9],-8;;
	ldf8		g0=[r9]
	ADDP		r8=32,in0		};;

{ .mfi;	xmpy.hu		h4h=g4,f_i		}
{ .mfi;	xmpy.lu		h4l=g4,f_i		}
{ .mfi;	xmpy.hu		h3h=g3,f_i		}
{ .mfi;	xmpy.lu		h3l=g3,f_i		}
{ .mfi;	xmpy.hu		h2h=g2,f_i		}
{ .mfi;	xmpy.lu		h2l=g2,f_i		}
{ .mfi;	xmpy.hu		h1h=g1,f_i		}
{ .mfi;	xmpy.lu		h1l=g1,f_i		}
{ .mfi;	xmpy.hu		h0h=g0,f_i		}
{ .mfi;	xmpy.lu		h0l=g0,f_i		};;

{ .mmi;	getf.sig	H4h=h4h
	getf.sig	H4l=h4l			}
{ .mmi;	getf.sig	H3h=h3h
	getf.sig	H3l=h3l			}
{ .mmi;	getf.sig	H2h=h2h
	getf.sig	H2l=h2l			}
{ .mmi;	getf.sig	H1h=h1h
	getf.sig	H1l=h1l			}
{ .mmb;	getf.sig	H0h=h0h
	getf.sig	H0l=h0l
	br.many		.Lreduction		};;
.endp	x25519_fe51_mul121666#

stringz	"X25519 primitives for IA64, CRYPTOGAMS by \@dot-asm"
