;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Performance in cycles per processed byte, streaming large buffers.
;;
;;		node.js v10	[scalar] asm
;;
;; Cortex-A7	25.0		6.35
;; Cortex-A15	12.0		3.85
;; Cortex-A53	11.0		2.69
;; Cortex-A57	6.6		2.70
;; POWER8	9.0		2.03
;; z13		9.0		2.30
;; Silvermont	7.0		2.83
;; Haswell	3.3		1.14
;;
;; Even though "WebAssembly aims to execute at native speed", the results
;; fall far from what respective platforms achieve. On 32-bit platforms
;; code generator apparently fails to note that upper halves of 64-bit
;; multiplicands are zeros and generates pair of redundant multiply-n-add
;; operations. And on 64-bit platforms, well, 64x64=128-bit multiplication
;; is out of reach, obviously...

(module
  (import "env" "memory" (memory 1))

  ;; globals are per-instance, so that if one needs two distinct contexts
  ;; at the same time, one has to create two instances...
  (global $H0 (mut i32) (i32.const 0))
  (global $H1 (mut i32) (i32.const 0))
  (global $H2 (mut i32) (i32.const 0))
  (global $H3 (mut i32) (i32.const 0))
  (global $H4 (mut i32) (i32.const 0))

  (global $R0 (mut i32) (i32.const 0))
  (global $R1 (mut i32) (i32.const 0))
  (global $R2 (mut i32) (i32.const 0))
  (global $R3 (mut i32) (i32.const 0))

  ;; void poly1305_init(poly1305_ctx *ctx, const unsigned char key[16]);
  ;;
  ;; |ctx| is ignored...
  ;;
  (func (export "poly1305_init") (param $ctx i32) (param $key i32)

    ;; init hash

    i32.const 0
    global.set $H0		;; ctx->h[0] = 0

    i32.const 0
    global.set $H1		;; ctx->h[1] = 0

    i32.const 0
    global.set $H2		;; ctx->h[2] = 0

    i32.const 0
    global.set $H3		;; ctx->h[3] = 0

    i32.const 0
    global.set $H4		;; ctx->h[4] = 0

    ;; init key

    local.get $key
    i32.load  offset=0 align=1
    i32.const 0x0fffffff
    i32.and
    global.set $R0		;; ctx->r[0] = key[0] & 0x0x0fffffff

    local.get $key
    i32.load  offset=4 align=1
    i32.const 0x0ffffffc
    i32.and
    global.set $R1		;; ctx->r[1] = key[1] & 0x0x0ffffffc

    local.get $key
    i32.load  offset=8 align=1
    i32.const 0x0ffffffc
    i32.and
    global.set $R2		;; ctx->r[2] = key[2] & 0x0x0ffffffc

    local.get $key
    i32.load  offset=12 align=1
    i32.const 0x0ffffffc
    i32.and
    global.set $R3		;; ctx->r[2] = key[2] & 0x0x0ffffffc
  )

  ;; void poly1305_blocks(poly1305_ctx *ctx, const void *inp, size_t len);
  ;;
  ;; |ctx| is ignored; the subroutine can be called multiple times, but if
  ;; |len| is not divisible by 16, last block is padded, so that it may
  ;; appear only in last call...
  ;;
  (func (export "poly1305_blocks") (param $ctx i32)
                                   (param $inp i32) (param $len i32)
    (local $h0 i32) (local $h1 i32) (local $h2 i32) (local $h3 i32)
    (local $h4 i32)
    (local $r0 i32) (local $r1 i32) (local $r2 i32) (local $r3 i32)
    (local $s1 i32) (local $s2 i32) (local $s3 i32) (local $c i32)
    (local $d0 i64) (local $d1 i64) (local $d2 i64) (local $d3 i64)

    local.get $len
    i32.eqz
    if
      return
    end

    ;; load the hash

    global.get $H0
    local.set $h0

    global.get $H1
    local.set $h1

    global.get $H2
    local.set $h2

    global.get $H3
    local.set $h3

    global.get $H4
    local.set $h4

    ;; load the key

    global.get $R0
    local.set $r0	;; r0 = ctx->r[0]

    global.get $R1
    local.tee $r1	;; r1 = ctx->r[1]
    i32.const 2
    i32.shr_u
    local.get $r1
    i32.add
    local.set $s1	;; s1 = r1 + (r1 >> 2)

    global.get $R2
    local.tee $r2	;; r2 = ctx->r[2]
    i32.const 2
    i32.shr_u
    local.get $r2
    i32.add
    local.set $s2	;; s2 = r2 + (r2 >> 2)

    global.get $R3
    local.tee $r3	;; r3 = ctx->r[3]
    i32.const 2
    i32.shr_u
    local.get $r3
    i32.add
    local.set $s3	;; s3 = r3 + (r3 >> 2)

    loop $loop

      ;; load input

      local.get $len
      i32.const 16
      i32.ge_u
      if		;; complete 16-byte block
        local.get $inp
        i64.load32_u  offset=0 align=1
        local.set $d0

        local.get $inp
        i64.load32_u  offset=4 align=1
        local.set $d1

        local.get $inp
        i64.load32_u  offset=8 align=1
        local.set $d2

        local.get $inp
        i64.load32_u  offset=12 align=1
        local.set $d3

        i32.const 1
        local.set $c
      else		;; partial block
        i64.const 0
        local.set $d1
        i64.const 0
        local.set $d2
        i64.const 0
        local.set $d3

        local.get $inp
        local.get $len
        call      $load_32_n_pad
        i64.extend_i32_u
        local.set $d0

        local.get $len
        i32.const 4
        i32.ge_u
        if
          local.get $inp
          i32.const 4
          i32.add
          local.get $len
          i32.const 4
          i32.sub
          call      $load_32_n_pad
          i64.extend_i32_u
          local.set $d1

          local.get $len
          i32.const 8
          i32.ge_u
          if
            local.get $inp
            i32.const 8
            i32.add
            local.get $len
            i32.const 8
            i32.sub
            call      $load_32_n_pad
            i64.extend_i32_u
            local.set $d2

            local.get $len
            i32.const 12
            i32.ge_u
            if
              local.get $inp
              i32.const 12
              i32.add
              local.get $len
              i32.const 12
              i32.sub
              call      $load_32_n_pad
              i64.extend_i32_u
              local.set $d3
            end
          end
        end

        i32.const 0
        local.set $c
        i32.const 16
        local.set $len
      end

      ;; accumulate input

      local.get $d0
      local.get $h0
      i64.extend_i32_u
      i64.add
      local.tee $d0
      i32.wrap_i64
      local.set $h0	;; h0 = (u32)(d0 = (u64)h0 + inp[0])

      local.get $d1
      local.get $h1
      i64.extend_i32_u
      i64.add
      local.get $d0
      i64.const 32
      i64.shr_u
      i64.add
      local.tee $d1
      i32.wrap_i64
      local.set $h1	;; h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + inp[1])

      local.get $d2
      local.get $h2
      i64.extend_i32_u
      i64.add
      local.get $d1
      i64.const 32
      i64.shr_u
      i64.add
      local.tee $d2
      i32.wrap_i64
      local.set $h2	;; h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + inp[2])

      local.get $d3
      local.get $h3
      i64.extend_i32_u
      i64.add
      local.get $d2
      i64.const 32
      i64.shr_u
      i64.add
      local.tee $d3
      i32.wrap_i64
      local.set $h3	;; h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + inp[3])

      local.get $d3
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      local.get $h4
      i32.add
      local.get $c
      i32.add
      local.set $h4	;; h4 += (u32)(d3 >> 32) + pad

      ;; multiply h4:h0 by key

      local.get $h0
      i64.extend_i32_u
      local.get $r0
      i64.extend_i32_u
      i64.mul		;; h0 * r0

      local.get $h1
      i64.extend_i32_u
      local.get $s3
      i64.extend_i32_u
      i64.mul		;; h1 * s3
      i64.add

      local.get $h2
      i64.extend_i32_u
      local.get $s2
      i64.extend_i32_u
      i64.mul		;; h2 * s2
      i64.add

      local.get $h3
      i64.extend_i32_u
      local.get $s1
      i64.extend_i32_u
      i64.mul		;; h3 * s1
      i64.add

      local.set $d0

      local.get $h0
      i64.extend_i32_u
      local.get $r1
      i64.extend_i32_u
      i64.mul		;; h0 * r1

      local.get $h1
      i64.extend_i32_u
      local.get $r0
      i64.extend_i32_u
      i64.mul		;; h1 * r0
      i64.add

      local.get $h2
      i64.extend_i32_u
      local.get $s3
      i64.extend_i32_u
      i64.mul		;; h2 * s3
      i64.add

      local.get $h3
      i64.extend_i32_u
      local.get $s2
      i64.extend_i32_u
      i64.mul		;; h3 * s2
      i64.add

      local.get $h4
      local.get $s1
      i32.mul		;; h4 * s1
      i64.extend_i32_u
      i64.add

      local.set $d1

      local.get $h0
      i64.extend_i32_u
      local.get $r2
      i64.extend_i32_u
      i64.mul		;; h0 * r2

      local.get $h1
      i64.extend_i32_u
      local.get $r1
      i64.extend_i32_u
      i64.mul		;; h1 * r1
      i64.add

      local.get $h2
      i64.extend_i32_u
      local.get $r0
      i64.extend_i32_u
      i64.mul		;; h2 * r0
      i64.add

      local.get $h3
      i64.extend_i32_u
      local.get $s3
      i64.extend_i32_u
      i64.mul		;; h3 * s3
      i64.add

      local.get $h4
      local.get $s2
      i32.mul		;; h4 * s2
      i64.extend_i32_u
      i64.add

      local.set $d2

      local.get $h0
      i64.extend_i32_u
      local.get $r3
      i64.extend_i32_u
      i64.mul		;; h0 * r3

      local.get $h1
      i64.extend_i32_u
      local.get $r2
      i64.extend_i32_u
      i64.mul		;; h1 * r2
      i64.add

      local.get $h2
      i64.extend_i32_u
      local.get $r1
      i64.extend_i32_u
      i64.mul		;; h2 * r1
      i64.add

      local.get $h3
      i64.extend_i32_u
      local.get $r0
      i64.extend_i32_u
      i64.mul		;; h3 * r0
      i64.add

      local.get $h4
      local.get $s3
      i32.mul		;; h4 * s3
      i64.extend_i32_u
      i64.add

      local.set $d3

      local.get $h4
      local.get $r0
      i32.mul

      local.set $h4

      ;; reduction step
      ;; a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0

      local.get $d0
      i32.wrap_i64
      local.set $h0	;; h0 = (u32)d0

      local.get $d0
      i64.const 32
      i64.shr_u
      local.get $d1
      i64.add
      local.tee $d1
      i32.wrap_i64
      local.set $h1	;; h1 = (u32)(d1 += d0 >> 32)

      local.get $d1
      i64.const 32
      i64.shr_u
      local.get $d2
      i64.add
      local.tee $d2
      i32.wrap_i64
      local.set $h2	;; h2 = (u32)(d2 += d1 >> 32)

      local.get $d2
      i64.const 32
      i64.shr_u
      local.get $d3
      i64.add
      local.tee $d3
      i32.wrap_i64
      local.set $h3	;; h3 = (u32)(d3 += d2 >> 32)

      local.get $d3
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      local.get $h4
      i32.add
      local.tee $h4	;; h4 += (u32)(d3 >> 32)

      ;; b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130

      i32.const 2
      i32.shr_u
      local.get $h4
      i32.const -4
      i32.and
      i32.add
      local.tee $c	;; c = (h4 >> 2) + (h4 & ~3)

      local.get $h4
      i32.const 3
      i32.and
      local.set $h4	;; h4 &= 3

      local.get $h0
      i32.add
      local.tee $h0	;; h0 += c
      local.get $c
      i32.lt_u
      local.tee $c

      local.get $h1
      i32.add
      local.tee $h1	;; h1 += c
      local.get $c
      i32.lt_u
      local.tee $c

      local.get $h2
      i32.add
      local.tee $h2	;; h2 += c
      local.get $c
      i32.lt_u
      local.tee $c

      local.get $h3
      i32.add
      local.tee $h3	;; h3 += c
      local.get $c
      i32.lt_u

      local.get $h4
      i32.add
      local.set $h4	;; h4 += c

      local.get $inp
      i32.const 16
      i32.add
      local.set $inp	;; inp += 16

      local.get $len
      i32.const 16
      i32.sub
      local.tee $len	;; len -= 16
      i32.const 0
      i32.gt_u
      br_if     $loop
    end

    ;; write the hash

    local.get $h0
    global.set $H0

    local.get $h1
    global.set $H1

    local.get $h2
    global.set $H2

    local.get $h3
    global.set $H3

    local.get $h4
    global.set $H4
  )

  ;; void poly1305_emit(poly1305_ctx *ctx, unsigned char out[16],
  ;;                    const unsigned char nonce[16]);
  ;; |ctx| is ignored...
  ;;
  (func (export "poly1305_emit") (param $ctx i32)
                                 (param $out i32) (param $nonce i32)
    (local $h0 i32) (local $h1 i32) (local $h2 i32) (local $h3 i32)
    (local $g0 i32) (local $g1 i32) (local $g2 i32) (local $g3 i32)
    (local $c i32) (local $t i64)

    ;; load the hash and compare to modulus

    global.get $H0
    local.tee $h0
    i32.const 5
    i32.add
    local.tee $g0
    i32.const 5
    i32.lt_u
    local.tee $c

    global.get $H1
    local.tee $h1
    i32.add
    local.tee $g1
    local.get $c
    i32.lt_u
    local.tee $c

    global.get $H2
    local.tee $h2
    i32.add
    local.tee $g2
    local.get $c
    i32.lt_u
    local.tee $c

    global.get $H3
    local.tee $h3
    i32.add
    local.tee $g3
    local.get $c
    i32.lt_u

    global.get $H4
    i32.add

    ;; check for carry

    i32.const 2
    i32.shr_u
    local.set $c

    ;; choose between hash and hash + 5

    local.get $g0
    local.get $h0
    local.get $c
    select
    local.set $h0

    local.get $g1
    local.get $h1
    local.get $c
    select
    local.set $h1

    local.get $g2
    local.get $h2
    local.get $c
    select
    local.set $h2

    local.get $g3
    local.get $h3
    local.get $c
    select
    local.set $h3

    ;; add nonce and write result

    local.get $out
    local.get $nonce
    i64.load32_u offset=0 align=1
    local.get $h0
    i64.extend_i32_u
    i64.add
    local.tee $t
    i64.store32 offset=0 align=1

    local.get $out
    local.get $nonce
    i64.load32_u offset=4 align=1
    local.get $h1
    i64.extend_i32_u
    i64.add
    local.get $t
    i64.const 32
    i64.shr_u
    i64.add
    local.tee $t
    i64.store32 offset=4 align=1

    local.get $out
    local.get $nonce
    i64.load32_u offset=8 align=1
    local.get $h2
    i64.extend_i32_u
    i64.add
    local.get $t
    i64.const 32
    i64.shr_u
    i64.add
    local.tee $t
    i64.store32 offset=8 align=1

    local.get $out
    local.get $nonce
    i64.load32_u offset=12 align=1
    local.get $h3
    i64.extend_i32_u
    i64.add
    local.get $t
    i64.const 32
    i64.shr_u
    i64.add
    i64.store32 offset=12 align=1
  )

  ;; static unsigned int load_32_n_pad(const unsigned int *inp, size_t len);
  ;;
  (func $load_32_n_pad (param $inp i32) (param $len i32)
                       (result i32)
    (local $ret i32)

    local.get $len
    i32.eqz
    if
      i32.const 1		;; 1<<0
      return
    end
    local.get $inp
    i32.load8_u offset=0
    local.set $ret

    local.get $len
    i32.const 1
    i32.eq
    if
      local.get $ret
      i32.const 0x100		;; 1<<8
      i32.or
      return
    end

    local.get $inp
    i32.load8_u offset=1
    i32.const 8
    i32.shl
    local.get $ret
    i32.or
    local.set $ret

    local.get $len
    i32.const 2
    i32.eq
    if
      local.get $ret
      i32.const 0x10000		;; 1<<16
      i32.or
      return
    end

    local.get $inp
    i32.load8_u offset=2
    i32.const 16
    i32.shl
    local.get $ret
    i32.or
    local.set $ret

    local.get $len
    i32.const 3
    i32.eq
    if
      local.get $ret
      i32.const 0x1000000	;; 1<<24
      i32.or
      return
    end

    local.get $inp
    i32.load8_u offset=3
    i32.const 24
    i32.shl
    local.get $ret
    i32.or
  )
)
