#!/usr/bin/env perl
#
# Why ILASM? Key to Keccak-1600 performance on 32-bit platforms is bit
# interleaving, which allows to simplify rotate operations. But it's
# less suitable for 64-bit platforms, by 30-40%. Ideally one wants both
# code paths to be available in .NET assembly for JIT compiler to choose
# from (yes, and even eliminate unused;-), depending on whether or not
# the module is *currently* executed on 32- or 64-bit platform. C++/CLI
# doesn't do, because it appears to insist on taking this decision at
# compile time, so that JIT would be presented with only one code path,
# not two. Not to mention that it drags along sizeable chunks of C RTL,
# which seems redundant. C# on the other hand doesn't give you enough
# control over inlining, and it's absolutely essential for performance
# that rotates get inlined. Raw CIL code allows to alleviate all these
# questions and ensure optimal all-round performance. Lane complementing
# KECCAK_1X variant was chosen for implementation. Below numbers are
# cycles per processed byte out of large buffer for r=1088, which
# corresponds to SHA3-256.
#
#		mono 4.2	.NET 4.7	[scalar] asm
#
# Cortex-A15	170		-		42
# Pentium M	151		-		59.5(*)
# Goldmont/32	150		87.1		52.0(*)
# Haswell/32	107		51.7		33.3(*)
#
# Cortex-A53	44.5		-		13
# Goldmont	28.7		25.5		15.8
# Haswell	20.5		17.0		9.6
#
# (*)	gcc-5.x-generated code, no [scalar] assembly;
#
# CONSTRAINTS.
#
# There is implicit dependency on byte order with rationale that all
# known .NET platforms are little-endian.
#
# It's expected that SHA3.CIL class is wrapped into something more
# presentable for .NET programmer. One can wonder if it makes sense
# to provide "unsafe" interface with byte * instead of byte[]...

my $class = "SHA3.CIL";

my @A = map([ "A$_"."0", "A$_"."1", "A$_"."2", "A$_"."3", "A$_"."4" ],
            (0, 1, 2, 3, 4));
my @T = map([ "T$_"."0", "T$_"."1", "T$_"."2", "T$_"."3", "T$_"."4" ],
            (0, 1));
my @C = map("C$_", (0..4));
my @D = map("D$_", (0..4));

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

sub ROL32
{ my ($val, $shift) = @_;
  my $snippet;
  my $ldval = ($val =~ m/^A/) ? "ldarg.0\n        " .
                                "ldfld unsigned int64 ${class}::$val"
                              : "ldloc $val";
    $snippet="$ldval\n";

    if ($shift == 1) {
    $snippet.=<<___;
        ldc.i4  32
        shl

        $ldval
        ldc.i4  32
        shr.un
        conv.u4
        dup
        stloc   AT
        ldc.i4.1
        shl
        ldloc   AT
        ldc.i4  31
        shr.un
        or              // $val.hi <<<= 1
        conv.u8

        or
___
    } elsif ($shift & 1) {
    my $lshift = $shift >> 1;
    my $rshift = 32-$lshift;
    $snippet.=<<___;
        conv.u4
        dup
        stloc   AT
        ldc.i4  $lshift
        shl
        ldloc   AT
        ldc.i4  $rshift
        shr.un
        or              // $val.lo <<<= $lshift
        conv.u8

        ldc.i4  32
        shl
___
    $lshift++;
    $rshift--;
    $snippet.=<<___;
        $ldval
        ldc.i4  32
        shr.un
        conv.u4
        dup
        stloc   AT
        ldc.i4  $lshift
        shl
        ldloc   AT
        ldc.i4  $rshift
        shr.un
        or              // $val.hi <<<= $lshift+1
        conv.u8

        or
___
    } elsif ($shift != 0) {
    my $lshift = $shift >> 1;
    my $rshift = 32 - $lshift;
    $snippet.=<<___;
        conv.u4
        dup
        stloc   AT
        ldc.i4  $lshift
        shl
        ldloc   AT
        ldc.i4  $rshift
        shr.un
        or              // $val.lo <<<= $lshift
        conv.u8

        $ldval
        ldc.i4  32
        shr.un
        conv.u4
        dup
        stloc   AT
        ldc.i4  $lshift
        shl
        ldloc   AT
        ldc.i4  $rshift
        shr.un
        or              // $val.hi <<<= $lshift
        conv.u8

        ldc.i4  32
        shl
        or
___
    }

    return $snippet;
}

sub ROL64
{ my ($val, $lshift) = @_;
  my $rshift = 64 - $lshift;
  my $snippet;
  my $ldval = ($val =~ m/^A/) ? "ldarg.0\n        " .
                                "ldfld   unsigned int64 ${class}::$val"
                              : "ldloc   $val";
    $snippet.="$ldval\n";
    if ($lshift != 0) {
    $snippet.=<<___;
        ldc.i4  $lshift
        shl
        $ldval
        ldc.i4  $rshift
        shr.un
        or              // $val <<<= $lshift
___
    }

    return $snippet;
}

$code.=<<___;
.assembly extern mscorlib { }

.class value private sequential ansi sealed beforefieldinit Keccak1600.Iotas
       extends [mscorlib]System.ValueType
{
    .pack 8
    .size 192
}

.class public sequential ansi beforefieldinit $class
       extends [mscorlib]System.Object
{
___
for (my $i=0; $i<5; $i++) {
  for (my $j=0; $j<5; $j++) {
$code.=<<___;
    .field private unsigned int64 $A[$i][$j]
___
  }
}
$code.=<<___;
    .field private static valuetype Keccak1600.Iotas iotas32 at iotas32
    .field private static valuetype Keccak1600.Iotas iotas64 at iotas64

    .method public hidebysig specialname rtspecialname
            instance void .ctor ()
    {
        ldarg.0
        call    instance void object::.ctor()

        ldarg.0
        call    instance void ${class}::Complement()

        ret
    }

    .method private hidebysig instance
    void Complement()
    {
        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[0][1]
        not
        stfld   unsigned int64 ${class}::$A[0][1]

        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[0][2]
        not
        stfld   unsigned int64 ${class}::$A[0][2]

        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[1][3]
        not
        stfld   unsigned int64 ${class}::$A[1][3]

        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[2][2]
        not
        stfld   unsigned int64 ${class}::$A[2][2]

        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[3][2]
        not
        stfld   unsigned int64 ${class}::$A[3][2]

        ldarg.0
        dup
        ldfld   unsigned int64 ${class}::$A[4][0]
        not
        stfld   unsigned int64 ${class}::$A[4][0]

        ret
    }

    .method private hidebysig static
    unsigned int64 BitInterleave(unsigned int64 v)
    {
        .locals (
            unsigned int32 lo,
            unsigned int32 hi,
            unsigned int32 t0,
            unsigned int32 t1 )

        sizeof  native int
        ldc.i4.8
        blt.s   Lproceed
        ldarg.0
        ret

    Lproceed:                   // JIT-eliminated on 64-bit platform
        ldarg.0
        dup
        conv.u4
        stloc   lo
        ldc.i4  32
        shr.un
        conv.u4
        stloc   hi

        ldloc   lo
        ldc.i4  0x55555555
        and
        dup
        ldc.i4.1
        shr.un
        or
        ldc.i4  0x33333333
        and
        dup
        ldc.i4.2
        shr.un
        or
        ldc.i4  0x0f0f0f0f
        and
        dup
        ldc.i4.4
        shr.un
        or
        ldc.i4  0x00ff00ff
        and
        dup
        ldc.i4.8
        shr.un
        or
        ldc.i4  0x0000ffff
        and
        stloc   t0

        ldloc   hi
        ldc.i4  0x55555555
        and
        dup
        ldc.i4.1
        shr.un
        or
        ldc.i4  0x33333333
        and
        dup
        ldc.i4.2
        shr.un
        or
        ldc.i4  0x0f0f0f0f
        and
        dup
        ldc.i4.4
        shr.un
        or
        ldc.i4  0x00ff00ff
        and
        dup
        ldc.i4.8
        shr.un
        or
        ldc.i4  16
        shl
        stloc   t1

        ldloc   lo
        ldc.i4  0xaaaaaaaa
        and
        dup
        ldc.i4.1
        shl
        or
        ldc.i4  0xcccccccc
        and
        dup
        ldc.i4.2
        shl
        or
        ldc.i4  0xf0f0f0f0
        and
        dup
        ldc.i4.4
        shl
        or
        ldc.i4  0xff00ff00
        and
        dup
        ldc.i4.8
        shl
        or
        ldc.i4  16
        shr.un
        stloc   lo

        ldloc   hi
        ldc.i4  0xaaaaaaaa
        and
        dup
        ldc.i4.1
        shl
        or
        ldc.i4  0xcccccccc
        and
        dup
        ldc.i4.2
        shl
        or
        ldc.i4  0xf0f0f0f0
        and
        dup
        ldc.i4.4
        shl
        or
        ldc.i4  0xff00ff00
        and
        dup
        ldc.i4.8
        shl
        or
        ldc.i4  0xffff0000
        and
        stloc   hi

        ldloc   lo
        ldloc   hi
        or
        conv.u8
        ldc.i4  32
        shl
        ldloc   t0
        ldloc   t1
        or
        conv.u8
        or

        ret
    }

    .method private hidebysig static
    unsigned int64 BitDeinterleave(unsigned int64 v)
    {
        .locals (
            unsigned int32 lo,
            unsigned int32 hi,
            unsigned int32 t0,
            unsigned int32 t1 )

        sizeof  native int
        ldc.i4.8
        blt.s   Lproceed
        ldarg.0
        ret

    Lproceed:                   // JIT-eliminated on 64-bit platform
        ldarg.0
        dup
        conv.u4
        stloc   lo
        ldc.i4  32
        shr.un
        conv.u4
        stloc   hi

        ldloc   lo
        ldc.i4  0x0000ffff
        and
        dup
        ldc.i4.8
        shl
        or
        ldc.i4  0x00ff00ff
        and
        dup
        ldc.i4.4
        shl
        or
        ldc.i4  0x0f0f0f0f
        and
        dup
        ldc.i4.2
        shl
        or
        ldc.i4  0x33333333
        and
        dup
        ldc.i4.1
        shl
        or
        ldc.i4  0x55555555
        and
        stloc   t0

        ldloc   hi
        ldc.i4  16
        shl
        dup
        ldc.i4.8
        shr.un
        or
        ldc.i4  0xff00ff00
        and
        dup
        ldc.i4.4
        shr.un
        or
        ldc.i4  0xf0f0f0f0
        and
        dup
        ldc.i4.2
        shr.un
        or
        ldc.i4  0xcccccccc
        and
        dup
        ldc.i4.1
        shr.un
        or
        ldc.i4  0xaaaaaaaa
        and
        stloc   t1

        ldloc   lo
        ldc.i4  16
        shr.un
        dup
        ldc.i4.8
        shl
        or
        ldc.i4  0x00ff00ff
        and
        dup
        ldc.i4.4
        shl
        or
        ldc.i4  0x0f0f0f0f
        and
        dup
        ldc.i4.2
        shl
        or
        ldc.i4  0x33333333
        and
        dup
        ldc.i4.1
        shl
        or
        ldc.i4  0x55555555
        and
        stloc   lo

        ldloc   hi
        ldc.i4  0xffff0000
        and
        dup
        ldc.i4.8
        shr.un
        or
        ldc.i4  0xff00ff00
        and
        dup
        ldc.i4.4
        shr.un
        or
        ldc.i4  0xf0f0f0f0
        and
        dup
        ldc.i4.2
        shr.un
        or
        ldc.i4  0xcccccccc
        and
        dup
        ldc.i4.1
        shr.un
        or
        ldc.i4  0xaaaaaaaa
        and
        stloc   hi

        ldloc   lo
        ldloc   hi
        or
        conv.u8
        ldc.i4  32
        shl
        ldloc   t0
        ldloc   t1
        or
        conv.u8
        or

        ret
    }
___

sub KeccakF1600 {
my ($bits) = @_;

$code.=<<___;
    .method private hidebysig instance
    void KeccakF1600_${bits}()
    {
        .locals (
            unsigned int64 C0,
            unsigned int64 C1,
            unsigned int64 C2,
            unsigned int64 C3,
            unsigned int64 C4,

            unsigned int64 D0,
            unsigned int64 D1,
            unsigned int64 D2,
            unsigned int64 D3,
            unsigned int64 D4,

            unsigned int64 T00,
            unsigned int64 T01,
            unsigned int64 T02,
            unsigned int64 T03,
            unsigned int64 T04,

            unsigned int64 T10,
            unsigned int64 T11,
            unsigned int64 T12,
            unsigned int64 T13,
            unsigned int64 T14,
            unsigned int64 *iota,
            int32 counter )
___
$code.=<<___    if ($bits == 64);
        sizeof  native int
        ldc.i4.8
        bge.s   Lproceed
        ret

    Lproceed:                   // JIT-eliminated on 32-bit platform
___
$code.=<<___    if ($bits == 32);
        .locals (
            unsigned int32 AT )

        sizeof  native int
        ldc.i4.8
        blt.s   Lproceed
        ret

    Lproceed:                   // JIT-eliminated on 64-bit platform
___
$code.=<<___;
        ldsflda valuetype Keccak1600.Iotas ${class}::iotas${bits}
        stloc   iota
        ldc.i4  24
        stloc   counter

    Loop:
___
for ($i = 0; $i < 5; $i++) {
$code.=<<___;
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][$i]
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][$i]
        xor
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][$i]
        xor
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][$i]
        xor
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][$i]
        xor
        stloc   $C[$i]
___
}
for ($i = 0; $i < 5; $i++) {
$code.=<<___;
        `&ROL${bits}("$C[($i+1)%5]",1)`
        ldloc   $C[($i+4)%5]
        xor
        stloc   $D[$i]
___
}
$code.=<<___;
        // T[0][0] = A[3][0] ^ C[0]; /* borrow T[0][0] */
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][0]
        ldloc   $D[0]
        xor
        stloc   $T[0][0]

        // T[0][1] = A[0][1] ^ D[1];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][1]
        ldloc   $D[1]
        xor
        stloc   $T[0][1]

        // T[0][2] = A[0][2] ^ D[2];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][2]
        ldloc   $D[2]
        xor
        stloc   $T[0][2]

        // T[0][3] = A[0][3] ^ D[3];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][3]
        ldloc   $D[3]
        xor
        stloc   $T[0][3]

        // T[0][4] = A[0][4] ^ D[4];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][4]
        ldloc   $D[4]
        xor
        stloc   $T[0][4]

        // C[0] =       A[0][0] ^ D[0]; /* rotate by 0 */
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[0][0]
        ldloc   $D[0]
        xor
        stloc   $C[0]

        // C[1] = ROL64(A[1][1] ^ D[1], rhotates[1][1]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][1]
        ldloc   $D[1]
        xor
        stloc   $C[1]
        `&ROL${bits}("$C[1]",$rhotates[1][1])`
        stloc   $C[1]

        // C[2] = ROL64(A[2][2] ^ D[2], rhotates[2][2]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][2]
        ldloc   $D[2]
        xor
        stloc   $C[2]
        `&ROL${bits}("$C[2]",$rhotates[2][2])`
        stloc   $C[2]

        // C[3] = ROL64(A[3][3] ^ D[3], rhotates[3][3]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][3]
        ldloc   $D[3]
        xor
        stloc   $C[3]
        `&ROL${bits}("$C[3]",$rhotates[3][3])`
        stloc   $C[3]

        // C[4] = ROL64(A[4][4] ^ D[4], rhotates[4][4]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][4]
        ldloc   $D[4]
        xor
        stloc   $C[4]
        `&ROL${bits}("$C[4]",$rhotates[4][4])`
        stloc   $C[4]

        // A[0][0] = C[0] ^ ( C[1] | C[2]) ^ iotas[i++];
        ldarg.0
        ldloc   $C[1]
        ldloc   $C[2]
        or
        ldloc   $C[0]
        xor
        ldloc   iota
        ldind.u8
        xor
        stfld   unsigned int64 ${class}::$A[0][0]
        ldloc   iota
        ldc.i4.8
        add
        stloc   iota

        // A[0][1] = C[1] ^ (~C[2] | C[3]);
        ldarg.0
        ldloc   $C[2]
        not
        ldloc   $C[3]
        or
        ldloc   $C[1]
        xor
        stfld   unsigned int64 ${class}::$A[0][1]

        // A[0][2] = C[2] ^ ( C[3] & C[4]);
        ldarg.0
        ldloc   $C[3]
        ldloc   $C[4]
        and
        ldloc   $C[2]
        xor
        stfld   unsigned int64 ${class}::$A[0][2]

        // A[0][3] = C[3] ^ ( C[4] | C[0]);
        ldarg.0
        ldloc   $C[4]
        ldloc   $C[0]
        or
        ldloc   $C[3]
        xor
        stfld   unsigned int64 ${class}::$A[0][3]

        // A[0][4] = C[4] ^ ( C[0] & C[1]);
        ldarg.0
        ldloc   $C[0]
        ldloc   $C[1]
        and
        ldloc   $C[4]
        xor
        stfld   unsigned int64 ${class}::$A[0][4]

        // T[1][0] = A[1][0] ^ D[0];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][0]
        ldloc   $D[0]
        xor
        stloc   $T[1][0]

        // T[1][1] = A[2][1] ^ D[1]; /* borrow T[1][1] */
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][1]
        ldloc   $D[1]
        xor
        stloc   $T[1][1]

        // T[1][2] = A[1][2] ^ D[2];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][2]
        ldloc   $D[2]
        xor
        stloc   $T[1][2]

        // T[1][3] = A[1][3] ^ D[3];
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][3]
        ldloc   $D[3]
        xor
        stloc   $T[1][3]

        // T[1][4] = A[2][4] ^ D[4]; /* borrow T[1][4] */
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][4]
        ldloc   $D[4]
        xor
        stloc   $T[1][4]

        // C[0] = ROL64(T[0][3],        rhotates[0][3]);
        `&ROL${bits}("$T[0][3]",$rhotates[0][3])`
        stloc   $C[0]

        // C[1] = ROL64(A[1][4] ^ D[4], rhotates[1][4]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[1][4]
        ldloc   $D[4]
        xor
        stloc   $C[1]
        `&ROL${bits}("$C[1]",$rhotates[1][4])`
        stloc   $C[1]

        // C[2] = ROL64(A[2][0] ^ D[0], rhotates[2][0]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][0]
        ldloc   $D[0]
        xor
        stloc   $C[2]
        `&ROL${bits}("$C[2]",$rhotates[2][0])`
        stloc   $C[2]

        // C[3] = ROL64(A[3][1] ^ D[1], rhotates[3][1]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][1]
        ldloc   $D[1]
        xor
        stloc   $C[3]
        `&ROL${bits}("$C[3]",$rhotates[3][1])`
        stloc   $C[3]

        // C[4] = ROL64(A[4][2] ^ D[2], rhotates[4][2]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][2]
        ldloc   $D[2]
        xor
        stloc   $C[4]
        `&ROL${bits}("$C[4]",$rhotates[4][2])`
        stloc   $C[4]

        // A[1][0] = C[0] ^ (C[1] |  C[2]);
        ldarg.0
        ldloc   $C[1]
        ldloc   $C[2]
        or
        ldloc   $C[0]
        xor
        stfld   unsigned int64 ${class}::$A[1][0]

        // A[1][1] = C[1] ^ (C[2] &  C[3]);
        ldarg.0
        ldloc   $C[2]
        ldloc   $C[3]
        and
        ldloc   $C[1]
        xor
        stfld   unsigned int64 ${class}::$A[1][1]

        // A[1][2] = C[2] ^ (C[3] | ~C[4]);
        ldarg.0
        ldloc   $C[3]
        ldloc   $C[4]
        not
        or
        ldloc   $C[2]
        xor
        stfld   unsigned int64 ${class}::$A[1][2]

        // A[1][3] = C[3] ^ (C[4] |  C[0]);
        ldarg.0
        ldloc   $C[4]
        ldloc   $C[0]
        or
        ldloc   $C[3]
        xor
        stfld   unsigned int64 ${class}::$A[1][3]

        // A[1][4] = C[4] ^ (C[0] &  C[1]);
        ldarg.0
        ldloc   $C[0]
        ldloc   $C[1]
        and
        ldloc   $C[4]
        xor
        stfld   unsigned int64 ${class}::$A[1][4]

        // C[0] = ROL64(T[0][1],        rhotates[0][1]);
        `&ROL${bits}("$T[0][1]",$rhotates[0][1])`
        stloc   $C[0]

        // C[1] = ROL64(T[1][2],        rhotates[1][2]);
        `&ROL${bits}("$T[1][2]",$rhotates[1][2])`
        stloc   $C[1]

        // C[2] = ROL64(A[2][3] ^ D[3], rhotates[2][3]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[2][3]
        ldloc   $D[3]
        xor
        stloc   $C[2]
        `&ROL${bits}("$C[2]",$rhotates[2][3])`
        stloc   $C[2]

        // C[3] = ROL64(A[3][4] ^ D[4], rhotates[3][4]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][4]
        ldloc   $D[4]
        xor
        stloc   $C[3]
        `&ROL${bits}("$C[3]",$rhotates[3][4])`
        stloc   $C[3]

        // C[4] = ROL64(A[4][0] ^ D[0], rhotates[4][0]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][0]
        ldloc   $D[0]
        xor
        stloc   $C[4]
        `&ROL${bits}("$C[4]",$rhotates[4][0])`
        stloc   $C[4]

        // A[2][0] =  C[0] ^ ( C[1] | C[2]);
        ldarg.0
        ldloc   $C[1]
        ldloc   $C[2]
        or
        ldloc   $C[0]
        xor
        stfld   unsigned int64 ${class}::$A[2][0]

        // A[2][1] =  C[1] ^ ( C[2] & C[3]);
        ldarg.0
        ldloc   $C[2]
        ldloc   $C[3]
        and
        ldloc   $C[1]
        xor
        stfld   unsigned int64 ${class}::$A[2][1]

        // A[2][2] =  C[2] ^ (~C[3] & C[4]);
        ldarg.0
        ldloc   $C[3]
        not
        ldloc   $C[4]
        and
        ldloc   $C[2]
        xor
        stfld   unsigned int64 ${class}::$A[2][2]

        // A[2][3] = ~C[3] ^ ( C[4] | C[0]);
        ldarg.0
        ldloc   $C[4]
        ldloc   $C[0]
        or
        ldloc   $C[3]
        not
        xor
        stfld   unsigned int64 ${class}::$A[2][3]

        // A[2][4] =  C[4] ^ ( C[0] & C[1]);
        ldarg.0
        ldloc   $C[0]
        ldloc   $C[1]
        and
        ldloc   $C[4]
        xor
        stfld   unsigned int64 ${class}::$A[2][4]

        // C[0] = ROL64(T[0][4],        rhotates[0][4]);
        `&ROL${bits}("$T[0][4]",$rhotates[0][4])`
        stloc   $C[0]

        // C[1] = ROL64(T[1][0],        rhotates[1][0]);
        `&ROL${bits}("$T[1][0]",$rhotates[1][0])`
        stloc   $C[1]

        // C[2] = ROL64(T[1][1],        rhotates[2][1]); /* originally A[2][1] */
        `&ROL${bits}("$T[1][1]",$rhotates[2][1])`
        stloc   $C[2]

        // C[3] = ROL64(A[3][2] ^ D[2], rhotates[3][2]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[3][2]
        ldloc   $D[2]
        xor
        stloc   $C[3]
        `&ROL${bits}("$C[3]",$rhotates[3][2])`
        stloc   $C[3]

        // C[4] = ROL64(A[4][3] ^ D[3], rhotates[4][3]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][3]
        ldloc   $D[3]
        xor
        stloc   $C[4]
        `&ROL${bits}("$C[4]",$rhotates[4][3])`
        stloc   $C[4]

        // A[3][0] =  C[0] ^ ( C[1] & C[2]);
        ldarg.0
        ldloc   $C[1]
        ldloc   $C[2]
        and
        ldloc   $C[0]
        xor
        stfld   unsigned int64 ${class}::$A[3][0]

        // A[3][1] =  C[1] ^ ( C[2] | C[3]);
        ldarg.0
        ldloc   $C[2]
        ldloc   $C[3]
        or
        ldloc   $C[1]
        xor
        stfld   unsigned int64 ${class}::$A[3][1]

        // A[3][2] =  C[2] ^ (~C[3] | C[4]);
        ldarg.0
        ldloc   $C[3]
        not
        ldloc   $C[4]
        or
        ldloc   $C[2]
        xor
        stfld   unsigned int64 ${class}::$A[3][2]

        // A[3][3] = ~C[3] ^ ( C[4] & C[0]);
        ldarg.0
        ldloc   $C[4]
        ldloc   $C[0]
        and
        ldloc   $C[3]
        not
        xor
        stfld   unsigned int64 ${class}::$A[3][3]

        // A[3][4] =  C[4] ^ ( C[0] | C[1]);
        ldarg.0
        ldloc   $C[0]
        ldloc   $C[1]
        or
        ldloc   $C[4]
        xor
        stfld   unsigned int64 ${class}::$A[3][4]

        // C[0] = ROL64(T[0][2],        rhotates[0][2]);
        `&ROL${bits}("$T[0][2]",$rhotates[0][2])`
        stloc   $C[0]

        // C[1] = ROL64(T[1][3],        rhotates[1][3]);
        `&ROL${bits}("$T[1][3]",$rhotates[1][3])`
        stloc   $C[1]

        // C[2] = ROL64(T[1][4],        rhotates[2][4]); /* originally A[2][4] */
        `&ROL${bits}("$T[1][4]",$rhotates[2][4])`
        stloc   $C[2]

        // C[3] = ROL64(T[0][0],        rhotates[3][0]); /* originally A[3][0] */
        `&ROL${bits}("$T[0][0]",$rhotates[3][0])`
        stloc   $C[3]

        // C[4] = ROL64(A[4][1] ^ D[1], rhotates[4][1]);
        ldarg.0
        ldfld   unsigned int64 ${class}::$A[4][1]
        ldloc   $D[1]
        xor
        stloc   $C[4]
        `&ROL${bits}("$C[4]",$rhotates[4][1])`
        stloc   $C[4]

        // A[4][0] =  C[0] ^ (~C[1] & C[2]);
        ldarg.0
        ldloc   $C[1]
        not
        ldloc   $C[2]
        and
        ldloc   $C[0]
        xor
        stfld   unsigned int64 ${class}::$A[4][0]

        // A[4][1] = ~C[1] ^ ( C[2] | C[3]);
        ldarg.0
        ldloc   $C[2]
        ldloc   $C[3]
        or
        ldloc   $C[1]
        not
        xor
        stfld   unsigned int64 ${class}::$A[4][1]

        // A[4][2] =  C[2] ^ ( C[3] & C[4]);
        ldarg.0
        ldloc   $C[3]
        ldloc   $C[4]
        and
        ldloc   $C[2]
        xor
        stfld   unsigned int64 ${class}::$A[4][2]

        // A[4][3] =  C[3] ^ ( C[4] | C[0]);
        ldarg.0
        ldloc   $C[4]
        ldloc   $C[0]
        or
        ldloc   $C[3]
        xor
        stfld   unsigned int64 ${class}::$A[4][3]

        // A[4][4] =  C[4] ^ ( C[0] & C[1]);
        ldarg.0
        ldloc   $C[0]
        ldloc   $C[1]
        and
        ldloc   $C[4]
        xor
        stfld   unsigned int64 ${class}::$A[4][4]

        ldloc   counter
        ldc.i4.1
        sub
        dup
        stloc   counter
        brtrue  Loop

        ret
    }

___
}

&KeccakF1600(64);
&KeccakF1600(32);

$code.=<<___;
    .method public hidebysig instance
    int32 Absorb(unsigned int8[] inp, int32 bsz)
    {
        .locals init (
            unsigned int8& pinned pinp,
            unsigned int64& pinned Aij )
        .locals (
            unsigned int64 *ptr,
            native unsigned int len,
            int32 counter )

        ldarg.1
        ldlen
        dup
        stloc   len
        ldarg.2
        blt.un  Ldone64

        ldarg.0
        ldflda  unsigned int64 ${class}::$A[0][0]
        stloc   Aij

        ldarg.1
        ldc.i4.0
        ldelema unsigned int8
        dup
        stloc   pinp
        conv.u
        stloc   ptr

        sizeof  native int
        ldc.i4.8
        blt.s   Lblock32

    Lblock64:
        ldc.i4.0
        stloc   counter         // counter = 0

    Loop64:
        ldloc   Aij
        ldloc   counter
        add
        dup
        ldind.u8
        ldloc   ptr
        unaligned. 1
        ldind.u8
        xor
        stind.i8

        ldloc   ptr
        ldc.i4.8
        add
        stloc   ptr             // ptr += 8
        ldloc   counter
        ldc.i4.8
        add
        dup
        stloc   counter         // counter -= 8
        ldarg.2
        blt.s   Loop64          // counter < bsz?

        ldarg.0
        call    instance void class ${class}::KeccakF1600_64()

        ldloc   len
        ldarg.2
        sub
        dup
        stloc   len             // len -= bsz
        ldarg.2
        bge.un  Loop64          // len >= bsz?

    Ldone64:
        ldloc   len
        conv.i4
        ret

    // 32-bit code path //////////////////////////////////////////////////////
    Lblock32:
        ldc.i4.0
        stloc   counter         // counter = 0

    Loop32:
        ldloc   Aij
        ldloc   counter
        add
        dup
        ldind.u8
        ldloc   ptr
        unaligned. 1
        ldind.u8
        call    unsigned int64 ${class}::BitInterleave(unsigned int64)
        xor
        stind.i8

        ldloc   ptr
        ldc.i4.8
        add
        stloc   ptr             // ptr += 8
        ldloc   counter
        ldc.i4.8
        add
        dup
        stloc   counter         // counter -= 8
        ldarg.2
        blt.s   Loop32          // counter < bsz?

        ldarg.0
        call    instance void class ${class}::KeccakF1600_32()

        ldloc   len
        ldarg.2
        sub
        dup
        stloc   len             // len -= bsz
        ldarg.2
        bge.un  Loop32          // len >= bsz?

    Ldone32:
        ldloc   len
        conv.i4
        ret
    }

    .method public hidebysig instance
    void Squeeze(unsigned int8[] res, int32 bsz)
    {
        .locals init (
            unsigned int8& pinned pres,
            unsigned int64& pinned Aij )
        .locals (
            unsigned int64 *ptr,
            native unsigned int len,
            int32 counter,
            unsigned int64 tail )

        ldarg.1
        ldlen
        dup
        stloc   len
        brfalse Ldone64

        ldarg.0
        ldflda  unsigned int64 ${class}::$A[0][0]
        stloc   Aij

        ldarg.1
        ldc.i4.0
        ldelema unsigned int8
        dup
        stloc   pres
        conv.u
        stloc   ptr

        ldarg.0
        call    instance void ${class}::Complement()

        ldc.i4.0
        stloc   counter

        sizeof  native int
        ldc.i4.8
        blt     Loop32

    Loop64:
        ldloc   len
        ldc.i4.8
        blt.un  Ltail64

        ldloc   ptr
        dup

        ldloc   Aij
        ldloc   counter
        add
        ldind.u8
        unaligned. 1
        stind.i8

        ldc.i4.8
        add
        stloc   ptr             // ptr += 8

        ldloc   len
        ldc.i4.8
        sub
        dup
        stloc   len             // len -= 8
        brfalse Ldone64         // len == 0?

        ldloc   counter
        ldc.i4.8
        add
        dup
        stloc   counter
        ldarg.2
        bne.un  Loop64

        ldarg.0
        call    instance void ${class}::Complement()
        ldarg.0
        call    instance void ${class}::KeccakF1600_64()
        ldarg.0
        call    instance void ${class}::Complement()
        ldc.i4.0
        stloc   counter
        br.s    Loop64

    Ltail64:
        ldloc   Aij
        ldloc   counter
        add
        ldind.u8
        stloc   tail

    Loop_tail64:
        ldloc   ptr
        dup
        ldloc   tail
        conv.i1
        stind.i1
        ldc.i4.1
        add
        stloc   ptr
        ldloc   tail
        ldc.i4.8
        shr
        stloc   tail
        ldloc   len
        ldc.i4.1
        sub
        dup
        stloc   len
        brtrue  Loop_tail64

    Ldone64:
        ret

    // 32-bit code path //////////////////////////////////////////////////////
    Loop32:
        ldloc   len
        ldc.i4.8
        blt.un  Ltail32

        ldloc   ptr
        dup

        ldloc   Aij
        ldloc   counter
        add
        ldind.u8
        call    unsigned int64 ${class}::BitDeinterleave(unsigned int64)
        unaligned. 1
        stind.i8

        ldc.i4.8
        add
        stloc   ptr             // ptr += 8

        ldloc   len
        ldc.i4.8
        sub
        dup
        stloc   len             // len -= 8
        brfalse Ldone32         // len == 0?

        ldloc   counter
        ldc.i4.8
        add
        dup
        stloc   counter
        ldarg.2
        bne.un  Loop32

        ldarg.0
        call    instance void ${class}::Complement()
        ldarg.0
        call    instance void ${class}::KeccakF1600_32()
        ldarg.0
        call    instance void ${class}::Complement()
        ldc.i4.0
        stloc   counter
        br.s    Loop32

    Ltail32:
        ldloc   Aij
        ldloc   counter
        add
        ldind.u8
        call    unsigned int64 ${class}::BitDeinterleave(unsigned int64)
        stloc   tail

    Loop_tail32:
        ldloc   ptr
        dup
        ldloc   tail
        conv.i1
        stind.i1
        ldc.i4.1
        add
        stloc   ptr
        ldloc   tail
        ldc.i4.8
        shr.un
        stloc   tail
        ldloc   len
        ldc.i4.1
        sub
        dup
        stloc   len
        brtrue  Loop_tail32

    Ldone32:
        ret
    }

    .data iotas32 = {
        int64(0x0000000000000001),  int64(0x0000008900000000),
        int64(0x8000008b00000000),  int64(0x8000808000000000),
        int64(0x0000008b00000001),  int64(0x0000800000000001),
        int64(0x8000808800000001),  int64(0x8000008200000001),
        int64(0x0000000b00000000),  int64(0x0000000a00000000),
        int64(0x0000808200000001),  int64(0x0000800300000000),
        int64(0x0000808b00000001),  int64(0x8000000b00000001),
        int64(0x8000008a00000001),  int64(0x8000008100000001),
        int64(0x8000008100000000),  int64(0x8000000800000000),
        int64(0x0000008300000000),  int64(0x8000800300000000),
        int64(0x8000808800000001),  int64(0x8000008800000000),
        int64(0x0000800000000001),  int64(0x8000808200000000)
    }
    .data iotas64 = {
        int64(0x0000000000000001),  int64(0x0000000000008082),
        int64(0x800000000000808a),  int64(0x8000000080008000),
        int64(0x000000000000808b),  int64(0x0000000080000001),
        int64(0x8000000080008081),  int64(0x8000000000008009),
        int64(0x000000000000008a),  int64(0x0000000000000088),
        int64(0x0000000080008009),  int64(0x000000008000000a),
        int64(0x000000008000808b),  int64(0x800000000000008b),
        int64(0x8000000000008089),  int64(0x8000000000008003),
        int64(0x8000000000008002),  int64(0x8000000000000080),
        int64(0x000000000000800a),  int64(0x800000008000000a),
        int64(0x8000000080008081),  int64(0x8000000000008080),
        int64(0x0000000080000001),  int64(0x8000000080008008)
    }
}
___

foreach(split("\n",$code)) {
    s/\`([^\`]*)\`/eval($1)/ge;
    print $_, "\n";
}
close STDOUT;
