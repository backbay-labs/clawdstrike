#ifndef _CRYPTOGAMS_SHA1_H
#define _CRYPTOGAMS_SHA1_H

#include <string.h>

/*
 * If SHA1_CTX conflicts with something, just redefine it to alternative
 * custom name prior including this header.
 */
typedef struct {
    unsigned int h[5];
    unsigned long long N;
    unsigned char buf[64];
    size_t off;
} SHA1_CTX;

void sha1_block_data_order(unsigned int *h, const void *inp, size_t blocks);

static void sha1_init(SHA1_CTX *ctx)
{
    ctx->h[0] = 0x67452301U;
    ctx->h[1] = 0xefcdab89U;
    ctx->h[2] = 0x98badcfeU;
    ctx->h[3] = 0x10325476U;
    ctx->h[4] = 0xc3d2e1f0U;
    ctx->N = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->off = 0;
}

static void sha1_update(SHA1_CTX *ctx, const void *inp, size_t len)
{
    size_t n;

    ctx->N += len;

    if ((n = ctx->off)) {
        size_t rem = sizeof(ctx->buf) - n;

        if (rem > len) {
            memcpy(ctx->buf + n, inp, len);
            ctx->off += len;
            return;
        } else {
            memcpy(ctx->buf + n, inp, rem);
            inp += rem;
            len -= rem;
            sha1_block_data_order(ctx->h, ctx->buf, 1);
            memset(ctx->buf, 0, sizeof(ctx->buf));
            ctx->off = 0;
        }
    }

    n = len / sizeof(ctx->buf);
    if (n > 0) {
        sha1_block_data_order(ctx->h, inp, n);
        n *= sizeof(ctx->buf);
        inp += n;
        len -= n;
    }

    if (len)
        memcpy(ctx->buf, inp, ctx->off = len);
}

#define __TOBE32(ptr, val) ((ptr)[0] = (unsigned char)((val)>>24), \
                            (ptr)[1] = (unsigned char)((val)>>16), \
                            (ptr)[2] = (unsigned char)((val)>>8),  \
                            (ptr)[3] = (unsigned char)(val))

static void sha1_final(unsigned char md[20], SHA1_CTX *ctx)
{
    unsigned long long bits = ctx->N * 8;
    size_t n = ctx->off;
    unsigned char *tail;
    unsigned int h_i;

    ctx->buf[n++] = 0x80;

    if (n <= (sizeof(ctx->buf) - 8)) {
        tail = ctx->buf + sizeof(ctx->buf) - 8;
        __TOBE32(tail, (unsigned int)(bits >> 32));
        __TOBE32(tail + 4, (unsigned int)bits);
        sha1_block_data_order(ctx->h, ctx->buf, 1);
    } else {
        unsigned char temp[2 * sizeof(ctx->buf)];

        memcpy(temp, ctx->buf, sizeof(ctx->buf));
        memset(temp + sizeof(ctx->buf), 0, sizeof(ctx->buf));
        tail = temp + sizeof(temp) - 8;
        __TOBE32(tail, (unsigned int)(bits >> 32));
        __TOBE32(tail + 4 , (unsigned int)bits);
        sha1_block_data_order(ctx->h, temp, 2);
    }

    h_i = ctx->h[0]; __TOBE32(md + 0, h_i);
    h_i = ctx->h[1]; __TOBE32(md + 4, h_i);
    h_i = ctx->h[2]; __TOBE32(md + 8, h_i);
    h_i = ctx->h[3]; __TOBE32(md + 12, h_i);
    h_i = ctx->h[4]; __TOBE32(md + 16, h_i);
}

#undef __TOBE32
#endif
