#!/usr/bin/env perl

######################################################################
## Constant-time SSSE3 AES core implementation.
## version 0.1
##
## By Mike Hamburg (Stanford University), 2009
## Public domain.
##
## For details see http://shiftleft.org/papers/vector_aes/ and
## http://crypto.stanford.edu/vpaes/.
##
######################################################################
# ARMv7 NEON adaptation by @dot-asm.
#
# Performance in cycles per byte processed with a 128-bit key out of a
# large buffer:
#		en/de
# Cortex-A5	51/72
# Cortex-A7	47/62
# Cortex-A8	38/53
# Cortex-A9	44/60
# Cortex-A15	27/35
# Snapdragon S4	45/65
#
# These are slower than table-based AES on corresponding processors,
# but we trade the performance for constant-time-ness.

$header=<<___;
typedef struct { unsigned long long opaque[31]; } vpaes_key;

int vpaes_set_encrypt_key(const unsigned char *key, int bits,
                          vpaes_key *schedule);
int vpaes_set_decrypt_key(const unsigned char *key, int bits,
                          vpaes_key *schedule);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const vpaes_key *schedule);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const vpaes_key *schedule);

/*
 * Process only complete blocks, or |length|-|length|%16 bytes.
 * The vpaes_cbc_encrypt also transitions to vpaes_cbc_decrypt
 * if the |key| was initialized with vpaes_set_decrypt_key.
 */
void vpaes_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const vpaes_key *schedule,
                       unsigned char *ivec);
void vpaes_cbc_decrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const vpaes_key *schedule,
                       unsigned char *ivec);
___

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code.=<<___;
.arch	armv7-a
.fpu	neon

.text
.syntax	unified
#if defined(__thumb2__) && !defined(__APPLE__)
# define adrl adr
.thumb
#else
.code	32
# undef	__thumb2__
#endif

.type	_vpaes_consts,%object
.align	7	@ totally strategic alignment
_vpaes_consts:
.Lk_mc_forward:	@ mc_forward
	.quad	0x0407060500030201, 0x0C0F0E0D080B0A09
	.quad	0x080B0A0904070605, 0x000302010C0F0E0D
	.quad	0x0C0F0E0D080B0A09, 0x0407060500030201
	.quad	0x000302010C0F0E0D, 0x080B0A0904070605
.Lk_mc_backward:@ mc_backward
	.quad	0x0605040702010003, 0x0E0D0C0F0A09080B
	.quad	0x020100030E0D0C0F, 0x0A09080B06050407
	.quad	0x0E0D0C0F0A09080B, 0x0605040702010003
	.quad	0x0A09080B06050407, 0x020100030E0D0C0F
.Lk_sr:		@ sr
	.quad	0x0706050403020100, 0x0F0E0D0C0B0A0908
	.quad	0x030E09040F0A0500, 0x0B06010C07020D08
	.quad	0x0F060D040B020900, 0x070E050C030A0108
	.quad	0x0B0E0104070A0D00, 0x0306090C0F020508

@
@ "Hot" constants
@
.Lk_inv:	@ inv, inva
	.quad	0x0E05060F0D080180, 0x040703090A0B0C02
	.quad	0x01040A060F0B0780, 0x030D0E0C02050809
.Lk_ipt:	@ input transform (lo, hi)
	.quad	0xC2B2E8985A2A7000, 0xCABAE09052227808
	.quad	0x4C01307D317C4D00, 0xCD80B1FCB0FDCC81
.Lk_sbo:	@ sbou, sbot
	.quad	0xD0D26D176FBDC700, 0x15AABF7AC502A878
	.quad	0xCFE474A55FBB6A00, 0x8E1E90D1412B35FA
.Lk_sb1:	@ sb1u, sb1t
	.quad	0x3618D415FAE22300, 0x3BF7CCC10D2ED9EF
	.quad	0xB19BE18FCB503E00, 0xA5DF7A6E142AF544
.Lk_sb2:	@ sb2u, sb2t
	.quad	0x69EB88400AE12900, 0xC2A163C8AB82234A
	.quad	0xE27A93C60B712400, 0x5EB7E955BC982FCD

@
@  Decryption stuff
@
.Lk_dipt:	@ decryption input transform
	.quad	0x0F505B040B545F00, 0x154A411E114E451A
	.quad	0x86E383E660056500, 0x12771772F491F194
.Lk_dsb9:	@ decryption sbox output *9*u, *9*t
	.quad	0x851C03539A86D600, 0xCAD51F504F994CC9
	.quad	0xC03B1789ECD74900, 0x725E2C9EB2FBA565
.Lk_dsbd:	@ decryption sbox output *D*u, *D*t
	.quad	0x7D57CCDFE6B1A200, 0xF56E9B13882A4439
	.quad	0x3CE2FAF724C6CB00, 0x2931180D15DEEFD3
.Lk_dsbb:	@ decryption sbox output *B*u, *B*t
	.quad	0xD022649296B44200, 0x602646F6B0F2D404
	.quad	0xC19498A6CD596700, 0xF3FF0C3E3255AA6B
.Lk_dsbe:	@ decryption sbox output *E*u, *E*t
	.quad	0x46F2929626D4D000, 0x2242600464B4F6B0
	.quad	0x0C55A6CDFFAAC100, 0x9467F36B98593E32
.Lk_dsbo:	@ decryption sbox final output
	.quad	0x1387EA537EF94000, 0xC7AA6DB9D4943E2D
	.quad	0x12D7560F93441D00, 0xCA4B8159D8C58E9C

@
@  Key schedule constants
@
.Lk_dksd:	@ decryption key schedule: invskew x*D
	.quad	0xFEB91A5DA3E44700, 0x0740E3A45A1DBEF9
	.quad	0x41C277F4B5368300, 0x5FDC69EAAB289D1E
.Lk_dksb:	@ decryption key schedule: invskew x*B
	.quad	0x9A4FCA1F8550D500, 0x03D653861CC94C99
	.quad	0x115BEDA7B6FC4A00, 0xD993256F7E3482C8
.Lk_dkse:	@ decryption key schedule: invskew x*E + 0x63
	.quad	0xD5031CCA1FC9D600, 0x53859A4C994F5086
	.quad	0xA23196054FDC7BE8, 0xCD5EF96A20B31487
.Lk_dks9:	@ decryption key schedule: invskew x*9
	.quad	0xB6116FC87ED9A700, 0x4AED933482255BFC
	.quad	0x4576516227143300, 0x8BB89FACE9DAFDCE

.Lk_rcon:	@ rcon
	.quad	0x1F8391B9AF9DEEB6, 0x702A98084D7C7D81

.Lk_opt:	@ output transform
	.quad	0xFF9F4929D6B66000, 0xF7974121DEBE6808
	.quad	0x01EDBD5150BCEC00, 0xE10D5DB1B05C0CE0
.Lk_deskew:	@ deskew tables: inverts the sbox's "skew"
	.quad	0x07E4A34047A4E300, 0x1DFEB95A5DBEF91A
	.quad	0x5F36B5DC83EA6900, 0x2841C2ABF49D1E77

.asciz  "Vector Permutation AES for ARMv7, Mike Hamburg (Stanford University)"
.size	_vpaes_consts,.-_vpaes_consts
.align	6
___

{
my ($inp,$out,$key) = map("r$_",(0..2));

$code.=<<___;
@
@  _aes_preheat
@
@  Fills register %r10 -> .aes_consts (so you can -fPIC)
@  and %xmm9-%xmm15 as specified below.
@
.type	_vpaes_enc_preheat,%function
.align	4
_vpaes_enc_preheat:
	adr		r10, .Lk_inv
	adr		r11, .Lk_sb1
	vmov.i8		q9, #0x0f		@ .Lk_s0F
	vld1.64		{q10-q11}, [r10]	@ .Lk_inv
	vld1.64		{q12-q13}, [r11]!	@ .Lk_sb1
	vld1.64		{q14-q15}, [r11]	@ .Lk_sb2
	bx		lr
.size	_vpaes_enc_preheat,.-_vpaes_enc_preheat

.type	_vpaes_dec_preheat,%function
.align	4
_vpaes_dec_preheat:
	adr		r10, .Lk_inv
	adr		r11, .Lk_dsb9
	vmov.i8		q9, #0x0f		@ .Lk_s0F
	vld1.64		{q10-q11}, [r10]	@ .Lk_inv
	vld1.64		{q12-q13}, [r11]	@ .Lk_dsb9
	bx		lr
.size	_vpaes_dec_preheat,.-_vpaes_dec_preheat

.type	_vpaes_key_preheat,%function
.align	4
_vpaes_key_preheat:
	adr		r10, .Lk_inv
	adr		r11, .Lk_sb1
	adr		r12, .Lk_ipt
	vmov.i8		q9, #0x0f		@ .Lk_s0F
	vld1.64		{q10-q11}, [r10]	@ .Lk_inv
	vld1.64		{q12-q13}, [r11]	@ .Lk_sb1
	vld1.64		{q14-q15}, [r12]	@ .Lk_ipt
	bx		lr
.size	_vpaes_key_preheat,.-_vpaes_key_preheat

@
@  _aes_encrypt_core
@
@  AES-encrypt %xmm0.
@
@  Inputs:
@     %xmm0 = input
@     %xmm9-%xmm15 as in _vpaes_enc_preheat
@    (%rdx) = scheduled keys
@
@  Output in %xmm0
@  Clobbers  %xmm1-%xmm5, %r9, %r10, %r11, %rax
@  Preserves %xmm6 - %xmm8 so you get some local vectors
@
.type	_vpaes_encrypt_core,%function
.align 4
_vpaes_encrypt_core:
	adr		r12, .Lk_ipt
	adr		r11, .Lk_mc_forward+16
	adr		r10, .Lk_sbo
	mov		r9, $key
	ldr		r8, [$key,#240]		@ pull rounds

	vld1.64		{q2-q3}, [r12]		@ iptlo
	vand		q1, q0, q9
	vshr.u8		q0, q0, #4
	vld1.64		{q5}, [r9]!		@ round0 key
	vtbl.8		q1, {q2}, q1
	vtbl.8		q0, {q3}, q0
	veor		q1, q1, q5
	ands		r8, r8, #~(1<<31)
	veor		q0, q0, q1
	b		.Lenc_entry

.align 4
.Loop_enc:
	@ middle of middle round
	vtbl.8		q4, {q13}, q2		@ 4 = sb1u
	add		r12, r11, #0x40
	vtbl.8		q0, {q12}, q3		@ 0 = sb1t
	veor		q4, q4, q5		@ 4 = sb1u + k
	vld1.64		{q1}, [r11]!		@ .Lk_mc_forward[]
	vtbl.8		q2, {q15}, q2		@ 4 = sb2u
	veor		q0, q0, q4		@ 0 = A
	vtbl.8		q3, {q14}, q3		@ 2 = sb2t
	vld1.64		{q4}, [r12]		@ .Lk_mc_backward[]
	veor		q2, q2, q3		@ 2 = 2A
	vtbl.8		q3, {q0}, q1		@ 0 = B
	and		r11, r11, #~(1<<6)	@ ... mod 4
	veor		q3, q3, q2		@ 0 = 2A+B
	vtbl.8		q4, {q0}, q4		@ 3 = D
	veor		q4, q4, q3		@ 3 = 2A+B+D
	vtbl.8		q1, {q3}, q1		@ 0 = 2B+C
	subs		r8, r8, #1		@ nr--
	veor		q0, q4, q1		@ 0 = 2A+3B+C+D

.Lenc_entry:
	@ top of round
	vand		q1, q0, q9		@ 0 = k
	vshr.u8		q0, q0, #4		@ 1 = i
	vtbl.8		q5, {q11}, q1		@ 2 = a/k
	veor		q1, q1, q0		@ 0 = j
	vtbl.8		q3, {q10}, q0		@ 3 = 1/i
	veor		q3, q3, q5		@ 3 = iak = 1/i + a/k
	vtbl.8		q4, {q10}, q1		@ 4 = 1/j
	veor		q4, q4, q5		@ 4 = jak = 1/j + a/k
	vtbl.8		q2, {q10}, q3		@ 2 = 1/iak
	veor		q2, q2, q1		@ 2 = io
	vtbl.8		q3, {q10}, q4		@ 3 = 1/jak
	vld1.64		{q5}, [r9]!
	veor		q3, q3, q0		@ 3 = jo
	bne		.Loop_enc

	@ middle of last round
	vld1.64		{q0-q1}, [r10]		@ 3 : sbou	.Lk_sbo
	add		r11, r11, #0x80
	vtbl.8		q2, {q0}, q2		@ 4 = sbou
	vtbl.8		q3, {q1}, q3		@ 0 = sb1t
	vld1.64		{q0}, [r11]		@ .Lk_sr[]
	veor		q2, q2, q5		@ 4 = sb1u + k
	veor		q2, q2, q3		@ 0 = A
	vtbl.8		q0, {q2}, q0

	bx		lr
.size	_vpaes_encrypt_core,.-_vpaes_encrypt_core

.globl	vpaes_encrypt
.type	vpaes_encrypt,%function
.align	4
vpaes_encrypt:
	stmdb		sp!, {r7-r11,lr}
	vstmdb		sp!, {d8-d15}

	vld1.8		{q0}, [$inp]
	bl		_vpaes_enc_preheat
	bl		_vpaes_encrypt_core
	vst1.8		{q0}, [$out]

	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_encrypt,.-vpaes_encrypt

@
@  Decryption core
@
@  Same API as encryption core.
@
.type	_vpaes_decrypt_core,%function
.align	4
_vpaes_decrypt_core:
	ldr		r8, [$key,#240]		@ pull rounds
	mov		r9, $key
	adr		r10, .Lk_dipt

	lsl		r11, r8, #4
	eor		r11, r11, #0x30
	adrl		r12, .Lk_sr
	and		r11, r11, #0x30
	add		r11, r11, r12
	adrl		r12, .Lk_mc_forward+48

	vld1.64		{q2-q3}, [r10]!		@ iptlo
	vld1.64		{q5}, [r9]!		@ round0 key
	vand		q1, q0, q9
	vshr.u8		q0, q0, #4
	vtbl.8		q1, {q2}, q1
	vtbl.8		q0, {q3}, q0
	veor		q1, q1, q5
	veor		q0, q0, q1
	vld1.64		{q5}, [r12]
	adds		r10, r10, #128
	b		.Ldec_entry

.align 4
.Loop_dec:
@
@  Inverse mix columns
@
	vtbl.8		q1, {q12}, q2		@ 4 = sb9u
	vtbl.8		q4, {q13}, q3		@ 0 = sb9t
	veor		q0, q0, q1
	veor		q0, q0, q4		@ 0 = ch

	vld1.64		{q14-q15}, [r10]!	@ 4 : sbdu
	vtbl.8		q1, {q0}, q5		@ MC ch
	vtbl.8		q0, {q14}, q2		@ 4 = sbdu
	veor		q0, q0, q1		@ 4 = ch
	vtbl.8		q4, {q15}, q3		@ 0 = sbdt
	veor		q0, q0, q4		@ 0 = ch

	vld1.64		{q14-q15}, [r10]!	@ 4 : sbbu
	vtbl.8		q1, {q0}, q5		@ MC ch
	vtbl.8		q0, {q14}, q2		@ 4 = sbbu
	veor		q0, q0, q1		@ 4 = ch
	vtbl.8		q4, {q15}, q3		@ 0 = sbbt
	veor		q0, q0, q4		@ 0 = ch

	vld1.64		{q14-q15}, [r10]!	@ 4 : sbeu
	vtbl.8		q1, {q0}, q5		@ MC ch
	vtbl.8		q0, {q14}, q2		@ 4 = sbeu
	veor		q0, q0, q1		@ 4 = ch
	vtbl.8		q4, {q15}, q3		@ 0 = sbet
	vext.8		q5, q5, q5, #12
	veor		q0, q0, q4		@ 0 = ch
	subs		r8, r8, #1		@ nr--

.Ldec_entry:
	@ top of round
	vshr.u8		q1, q0, #4		@ 1 = i
	vand		q0, q0, q9		@ 0 = k
	vtbl.8		q3, {q10}, q1		@ 3 = 1/i
	vtbl.8		q2, {q11}, q0		@ 2 = a/k
	veor		q0, q0, q1		@ 0 = j
	veor		q3, q3, q2		@ 3 = iak = 1/i + a/k
	vtbl.8		q4, {q10}, q0		@ 4 = 1/j
	veor		q4, q4, q2		@ 4 = jak = 1/j + a/k
	vtbl.8		q3, {q10}, q3		@ 2 = 1/iak
	veor		q2, q3, q0		@ 2 = io
	vtbl.8		q4, {q10}, q4		@ 3 = 1/jak
	vld1.64		{q0}, [r9]!
	it		ne
	subne		r10, r10, #96
	veor		q3, q4, q1		@ 3 = jo
	bne		.Loop_dec

	@ middle of last round
	vld1.64		{q4-q5}, [r10]		@ 3 : sbou
	vtbl.8		q2, {q4}, q2		@ 4 = sbou
	vtbl.8		q3, {q5}, q3		@ 0 = sb1t
	vld1.64		{q4}, [r11]
	veor		q2, q2, q0		@ 4 = sb1u + k
	veor		q2, q2, q3		@ 0 = A
	vtbl.8		q0, {q2}, q4
	bx		lr
.size	_vpaes_decrypt_core,.-_vpaes_decrypt_core

.globl	vpaes_decrypt
.type	vpaes_decrypt,%function
.align	4
vpaes_decrypt:
	stmdb		sp!, {r7-r11,lr}
	vstmdb		sp!, {d8-d15}

	vld1.8		{q0}, [$inp]
	bl		_vpaes_dec_preheat
	bl		_vpaes_decrypt_core
	vst1.8		{q0}, [$out]

	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_decrypt,.-vpaes_decrypt
___
}
{
my ($inp,$out,$len,$key,$ivec) = map("r$_",(0..3,3));

$code.=<<___;
.globl	vpaes_cbc_encrypt
.type	vpaes_cbc_encrypt,%function
.align	4
vpaes_cbc_encrypt:
	cmp		$len, #16
	it		lo
	bxlo		lr

	stmdb		sp!, {r7-r11,lr}
	mov		r7, $len		@ reassign
	ldr		r8, [$key, #240]
	mov		r2, $key		@ reassign
	ldr		$ivec, [sp, #6*4]
	vstmdb		sp!, {d8-d15}

	tst		r8, #1<<31		@ check direction
	beq		.Lcbc_decrypt


	vld1.8		{q6}, [$ivec]		@ load ivec
	bl		_vpaes_enc_preheat

.Loop_cbc_enc:
	vld1.8		{q0}, [$inp]!		@ load input
	veor		q0, q0, q6		@ xor with ivec
	bl		_vpaes_encrypt_core
	vmov		q6, q0
	vst1.8		{q0}, [$out]!		@ save output
	subs		r7, r7, #16
	bhi		.Loop_cbc_enc

	vst1.8		{q6}, [$ivec]		@ write ivec

	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_cbc_encrypt,.-vpaes_cbc_encrypt

.globl	vpaes_cbc_decrypt
.type	vpaes_cbc_decrypt,%function
.align	4
vpaes_cbc_decrypt:
	cmp		$len, #16
	it		lo
	bxlo		lr

	stmdb		sp!, {r7-r11,lr}
	mov		r7, $len		@ reassign
	mov		r2, $key		@ reassign
	ldr		$ivec, [sp, #8*4]
	vstmdb		sp!, {d8-d15}

.Lcbc_decrypt:

	vld1.8		{q6}, [$ivec]		@ load ivec
	bl		_vpaes_dec_preheat

.Loop_cbc_dec:
	vld1.8		{q0}, [$inp]!		@ load input
	vmov		q7, q0
	bl		_vpaes_decrypt_core
	veor		q0, q0, q6		@ xor with ivec
	vmov		q6, q7			@ next ivec value
	vst1.8		{q0}, [$out]!
	subs		r7, r7, #16
	bhi		.Loop_cbc_dec

	vst1.8		{q6}, [$ivec]

	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_cbc_decrypt,.-vpaes_cbc_decrypt
___
}
{
my ($inp,$bits,$out,$dir)=map("r$_", (0..3));

$code.=<<___;
.type	_vpaes_schedule_core,%function
.align	4
_vpaes_schedule_core:
	stmdb		sp!, {lr}

	bl		_vpaes_key_preheat	@ load the tables

	adrl		r11, .Lk_rcon
	vld1.8		{q0}, [$inp]!		@ load key (unaligned)
	vld1.64		{q8}, [r11]		@ load rcon

	@ input transform
	vmov		q3, q0
	bl		_vpaes_schedule_transform
	vmov		q7, q0

	adrl		r10, .Lk_sr
	add		r8, r8, r10
	tst		$dir, $dir
	bne		.Lschedule_am_decrypting

	@ encrypting, output zeroth round key after transform
	vst1.64		{q0}, [$out]
	b		.Lschedule_go

.Lschedule_am_decrypting:
	@ decrypting, output zeroth round key after shiftrows
	vld1.64		{q1}, [r8]
	vtbl.8		q1, {q3}, q1
	vst1.64		{q1}, [$out]
	vmov		q3, q1
	eor		r8, r8, #0x30

.Lschedule_go:
	cmp		$bits, #192
	bhi		.Lschedule_256
	beq		.Lschedule_192
	@ 128: fall though

@
@  .schedule_128
@
@  128-bit specific part of key schedule.
@
@  This schedule is really simple, because all its parts
@  are accomplished by the subroutines.
@
.Lschedule_128:
	mov	$inp, #10
	b	.Loop_schedule_128

.align	4
.Loop_schedule_128:
	bl 		_vpaes_schedule_round
	subs		$inp, $inp, #1
	beq 		.Lschedule_mangle_last
	bl		_vpaes_schedule_mangle	@ write output
	b 		.Loop_schedule_128

@
@  .aes_schedule_192
@
@  192-bit specific part of key schedule.
@
@  The main body of this schedule is the same as the 128-bit
@  schedule, but with more smearing.  The long, high side is
@  stored in %xmm7 as before, and the short, low side is in
@  the high bits of %xmm6.
@
@  This schedule is somewhat nastier, however, because each
@  round produces 192 bits of key material, or 1.5 round keys.
@  Therefore, on each cycle we do 2 rounds and produce 3 round
@  keys.
@
.align	4
.Lschedule_192:
	sub		$inp, $inp, #8
	vld1.8		{q0}, [$inp]		@ load key part 2 (very unaligned)
	bl		_vpaes_schedule_transform
	vmov		q6, q0			@ save short part
	vmov.i8		q4, #0			@ clear 4
	vmov.i8		d12, #0			@ clobber low side with zeros
	mov		$inp, #4
	b		.Loop_schedule_192

.align	4
.Loop_schedule_192:
	bl		_vpaes_schedule_round
	vext.8		q0, q6, q0, #8
	bl		_vpaes_schedule_mangle	@ save key n
	bl		_vpaes_schedule_192_smear
	bl		_vpaes_schedule_mangle	@ save key n+1
	bl		_vpaes_schedule_round
	subs		$inp, $inp, #1
	beq	 	.Lschedule_mangle_last
	bl		_vpaes_schedule_mangle	@ save key n+2
	bl		_vpaes_schedule_192_smear
	b		.Loop_schedule_192

@
@  .aes_schedule_256
@
@  256-bit specific part of key schedule.
@
@  The structure here is very similar to the 128-bit
@  schedule, but with an additional "low side" in
@  %xmm6.  The low side's rounds are the same as the
@  high side's, except no rcon and no rotation.
@
.align	4
.Lschedule_256:
	vld1.8		{q0}, [$inp]		@ load key part 2 (unaligned)
	bl		_vpaes_schedule_transform
	mov		$inp, #7
	b		.Loop_schedule_256

.align	4
.Loop_schedule_256:
	bl		_vpaes_schedule_mangle	@ output low result
	vmov		q6, q0			@ save cur_lo in xmm6

	@ high round
	bl		_vpaes_schedule_round
	subs		$inp, $inp, #1
	beq		.Lschedule_mangle_last
	bl		_vpaes_schedule_mangle

	@ low round. swap xmm7 and xmm6
	vdup.32		q0, d1[1]
	vmov		q5, q7
	vmov		q7, q6
	vmov.i8		q4, #0
	bl		_vpaes_schedule_low_round
	vmov		q7, q5
	b		.Loop_schedule_256

@
@  .aes_schedule_mangle_last
@
@  Mangler for last round of key schedule
@  Mangles %xmm0
@    when encrypting, outputs out(%xmm0) ^ 63
@    when decrypting, outputs unskew(%xmm0)
@
@  Always called right before return... jumps to cleanup and exits
@
.align	4
.Lschedule_mangle_last:
	adrl		r11, .Lk_deskew
	tst		$dir, $dir
	bne		.Lschedule_mangle_last_dec

	@ encrypting
	vld1.64		{q0}, [r8]
	adrl		r11, .Lk_opt
	add		$out, $out, #32
	vtbl.8		q0, {q7}, q0

.Lschedule_mangle_last_dec:
	vld1.64		{q14-q15}, [r11]
	vmov.i8		q1, #0x5b		@ .Lk_s63
	veor		q0, q0, q1
	sub		$out, $out, #16
	bl		_vpaes_schedule_transform
	vst1.64		{q0}, [$out]

	ldmia		sp!, {pc}
.size	_vpaes_schedule_core,.-_vpaes_schedule_core

@
@  .aes_schedule_192_smear
@
@  Smear the short, low side in the 192-bit key schedule.
@
@  Inputs:
@    %xmm7: high side, b  a  x  y
@    %xmm6:  low side, d  c  0  0
@    %xmm13: 0
@
@  Outputs:
@    %xmm6: b+c+d  b+c  0  0
@    %xmm0: b+c+d  b+c  b  a
@
.type	_vpaes_schedule_192_smear,%function
.align	4
_vpaes_schedule_192_smear:
	vshl.i64	q1, q6, #32		@ d c 0 0 -> c 0 0 0
	vmov		d0, d15			@ q0[0] = q7[1]
	vdup.32		d1, d15[1]		@ b a _ _ -> b b b a
	veor		q6, q6, q1		@ -> c+d c 0 0
	veor		q6, q6, q0		@ -> b+c+d b+c b a
	vmov		q0, q6
	vmov.i8		d12, #0			@ clobber low side with zeros
	bx		lr
.size	_vpaes_schedule_192_smear,.-_vpaes_schedule_192_smear

@
@  .aes_schedule_round
@
@  Runs one main round of the key schedule on %xmm0, %xmm7
@
@  Specifically, runs subbytes on the high dword of %xmm0
@  then rotates it by one byte and xors into the low dword of
@  %xmm7.
@
@  Adds rcon from low byte of %xmm8, then rotates %xmm8 for
@  next rcon.
@
@  Smears the dwords of %xmm7 by xoring the low into the
@  second low, result into third, result into highest.
@
@  Returns results in %xmm7 = %xmm0.
@  Clobbers %xmm1-%xmm4, %r11.
@
.type	_vpaes_schedule_round,%function
.align	4
_vpaes_schedule_round:
	@ extract rcon from xmm8
	vmov.i8		q4, #0
	vext.8		q1, q8, q4, #15
	vext.8		q8, q8, q8, #15
	veor		q7, q7, q1

	@ rotate
	vdup.32		q0, d1[1]
	vext.8		q0, q0, q0, #1

	@ fall through...

	@ low round: same as high round, but no rotation and no rcon.
_vpaes_schedule_low_round:
	@ smear xmm7
	vext.8		q1, q4, q7, #12
	veor		q7, q7, q1
	vext.8		q1, q4, q7, #8
	veor		q7, q7, q1
	vmov.i8		q1, #0x5b		@ .Lk_s63
	veor		q7, q7, q1

	@ subbytes
	vshr.u8		q1, q0, #4		@ 1 = i
	vand		q0, q0, q9		@ 0 = k
	vtbl.8		q2, {q11}, q0		@ 2 = a/k
	veor		q0, q0, q1		@ 0 = j
	vtbl.8		q3, {q10}, q1		@ 3 = 1/i
	veor		q3, q3, q2		@ 3 = iak = 1/i + a/k
	vtbl.8		q4, {q10}, q0		@ 4 = 1/j
	veor		q4, q4, q2		@ 4 = jak = 1/j + a/k
	vtbl.8		q2, {q10}, q3		@ 2 = 1/iak
	veor		q2, q2, q0		@ 2 = io
	vtbl.8		q3, {q10}, q4		@ 3 = 1/jak
	veor		q3, q3, q1		@ 3 = jo
	vtbl.8		q4, {q13}, q2		@ 4 = sbou
	vtbl.8		q0, {q12}, q3		@ 0 = sb1t
	veor		q0, q0, q4		@ 0 = sbox output

	@ add in smeared stuff
	veor		q0, q0, q7
	vmov		q7, q0
	bx		lr
.size	_vpaes_schedule_round,.-_vpaes_schedule_round

@
@  .aes_schedule_transform
@
@  Linear-transform %xmm0 according to tables at (%r11)
@
@  Requires that %xmm9 = 0x0F0F... as in preheat
@  Output in %xmm0
@  Clobbers %xmm1, %xmm2
@
.type	_vpaes_schedule_transform,%function
.align	4
_vpaes_schedule_transform:
	vand		q1, q0, q9
	vshr.u8		q0, q0, #4
	vtbl.8		q1, {q14}, q1
	vtbl.8		q0, {q15}, q0
	veor		q0, q0, q1
	bx		lr
.size	_vpaes_schedule_transform,.-_vpaes_schedule_transform

@
@  .aes_schedule_mangle
@
@  Mangle xmm0 from (basis-transformed) standard version
@  to our version.
@
@  On encrypt,
@    xor with 0x63
@    multiply by circulant 0,1,1,1
@    apply shiftrows transform
@
@  On decrypt,
@    xor with 0x63
@    multiply by "inverse mixcolumns" circulant E,B,D,9
@    deskew
@    apply shiftrows transform
@
@
@  Writes out to (%rdx), and increments or decrements it
@  Keeps track of round number mod 4 in %r8
@  Preserves xmm0
@  Clobbers xmm1-xmm5
@
.type	_vpaes_schedule_mangle,%function
.align	4
_vpaes_schedule_mangle:
	vmov		q4, q0			@ save xmm0 for later
	adrl		r12, .Lk_mc_forward
	vld1.64		{q5}, [r12]
	tst		$dir, $dir
	bne		.Lschedule_mangle_dec

	@ encrypting
	add		$out, $out, #16
	vmov.i8		q1, #0x5b		@ .Lk_s63
	veor		q4, q4, q1
	vtbl.8		q1, {q4}, q5
	vtbl.8		q3, {q1}, q5
	veor		q4, q1, q3
	vtbl.8		q1, {q3}, q5
	veor		q4, q4, q1
	b		.Lschedule_mangle_both

.align	4
.Lschedule_mangle_dec:
	@ # inverse mix columns
	adrl		r11, .Lk_dksd
	@ #movdqa	%xmm9,	%xmm1
	@ vpandn	%xmm4,	%xmm9, %xmm1
	vshr.u8		q1, q4, #4		@ 1 = hi
	vand		q4, q4, q9		@ 4 = lo

	vld1.64		{q14-q15}, [r11]!
	vtbl.8		q2, {q14}, q4
	vtbl.8		q3, {q15}, q1
	veor		q3, q3, q2
	vtbl.8		q2, {q3}, q5

	vld1.64		{q14-q15}, [r11]!
	vtbl.8		q3, {q14}, q4
	veor		q2, q2, q3
	vtbl.8		q3, {q15}, q1
	veor		q3, q3, q2
	vtbl.8		q2, {q3}, q5

	vld1.64		{q14-q15}, [r11]!
	vtbl.8		q3, {q14}, q4
	veor		q2, q2, q3
	vtbl.8		q3, {q15}, q1
	veor		q3, q3, q2
	vtbl.8		q2, {q3}, q5

	vld1.64		{q14-q15}, [r11]
	vtbl.8		q3, {q14}, q4
	veor		q2, q2, q3
	vtbl.8		q3, {q15}, q1
	veor		q4, q3, q2

	sub		$out, $out, #16

.Lschedule_mangle_both:
	vld1.64		{q1}, [r8]
	vtbl.8		q3, {q4}, q1
	add		r8, r8, #64-16
	and		r8, r8, #~(1<<6)
	vst1.64		{q3}, [$out]
	bx		lr
.size	_vpaes_schedule_mangle,.-_vpaes_schedule_mangle

.globl	vpaes_set_encrypt_key
.type	vpaes_set_encrypt_key,%function
.align	4
vpaes_set_encrypt_key:
	stmdb		sp!, {r7-r11,lr}
	vstmdb		sp!, {d8-d15}

	lsr		r9, $bits, #5
	add		r9, r9, #5
	orr		r8, r9, #1<<31		@ record the direction
	str		r8, [$out,#240]		@ AES_KEY->rounds = nbits/32+5;

	mov		$dir, #0
	mov		r8, #0x30
	bl		_vpaes_schedule_core

	eor		r0, r0, r0
	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_set_encrypt_key,.-vpaes_set_encrypt_key

.globl	vpaes_set_decrypt_key
.type	vpaes_set_decrypt_key,%function
.align	4
vpaes_set_decrypt_key:
	stmdb		sp!, {r7-r11,lr}
	vstmdb		sp!, {d8-d15}

	lsr		r9, $bits, #5
	add		r9, r9, #5
	str		r9, [$out,#240]		@ AES_KEY->rounds = nbits/32+5;
	lsl		r9, r9, #4
	add		$out, $out, #16
	add		$out, $out, r9

	mov		$dir, #1
	lsr		r8, $bits, #1
	and		r8, r8, #32
	eor		r8, r8, #32		@ nbits==192?0:32
	bl		_vpaes_schedule_core

	eor		r0, r0, r0
	vldmia		sp!, {d8-d15}
	ldmia		sp!, {r7-r11,pc}
.size	vpaes_set_decrypt_key,.-vpaes_set_decrypt_key
___
}

foreach(split("\n",$code)) {
	s/\bvtbl\.8\s+q([0-9]+),\s*\{q([0-9]+)\},\s*q([0-9]+)\b/
	  sprintf "vtbl.8 d%d,{q$2},d%d\n\t".
		  "vtbl.8 d%d,{q$2},d%d", $1*2, $3*2, $1*2+1, $3*2+1
	 /eo;

	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
