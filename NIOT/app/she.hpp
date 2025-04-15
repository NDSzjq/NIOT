#ifndef SHE_H
#define SHE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "e_os.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
//#include "bn_lcl.h"

// #define DEFAULT_K0 2048
// #define DEFAULT_K1 20
// #define DEFAULT_K2 1000

#define DEFAULT_P 1024
#define DEFAULT_Q 1100
#define DEFAULT_M 40
#define DEFAULT_L 160
#define DEFAULT_N DEFAULT_P+DEFAULT_Q





#define stdout ((void *)1)
#define stderr ((void *)2)
#define putc(c, stream) printf("%c", c)

/* SHE keys */
typedef struct _SHE_key {
        BIGNUM *p, *q,*l,*n,*ld2;
} SHE_key;

int generateRandomKeys_she(SHE_key *key, BN_CTX *ctx)
{
    // BN_GENCB cb;
    int ret = 1;
    BIGNUM *p, *q, *l, *n, *ld2;

    BN_CTX_start(ctx);

    p = BN_new();
    q = BN_new();
    l = BN_new();
    n = BN_new();
    ld2 = BN_new();


    // 1. Choose two large prime numbers and a random number l
    do
    {
        // BN_GENCB_set(&cb, genprime_cb, NULL);
        if (!BN_generate_prime_ex(p, DEFAULT_Q, 0, NULL, NULL, NULL))
            goto end;
        if (!BN_generate_prime_ex(q, DEFAULT_P, 0, NULL, NULL, NULL))
            goto end;
        if (!BN_rand(l, DEFAULT_L, 0, 0))
            goto end;
    }
    while (BN_cmp(p, q) == 0 || BN_is_zero(l));

    if (!BN_mul(n, p, q, ctx))
            goto end;

    if(!BN_rshift1(ld2, l))
        goto end;

    key->p = p;
    key->q = q;
    key->l = l;
    key->n = n;
    key->ld2 = ld2;

    ret = 0;
end:
    if (ret)
    {
        printf("key generation error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int encrypt_she(BIGNUM *c, const BIGNUM *m, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *r = BN_CTX_get(ctx);
    BIGNUM *r_ = BN_CTX_get(ctx);
    BIGNUM *n = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    do
    {
        if (!BN_rand(r, DEFAULT_L, 0, 0))
            goto end;
    } while (BN_is_zero(r));

    do
    {
        if (!BN_rand(r_, DEFAULT_Q, 0, 0))
            goto end;
    } while (BN_is_zero(r_));

    if (!BN_mul(n, key->p, key->q, ctx))
        goto end;
    if (!BN_mod_mul(tmp1, r, key->l, n, ctx))
        goto end;
    if (!BN_mod_add(tmp1, tmp1, m, n, ctx))
        goto end;
    if (!BN_mod_mul(tmp2, r_, key->p, n, ctx))
        goto end;
    if (!BN_add_word(tmp2, 1))
        goto end;
    if (!BN_mod_mul(c, tmp1, tmp2, n, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}

int decrypt_she(BIGNUM *plain, const BIGNUM *c, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);
    if (!BN_mod(tmp, c, key->p, ctx))
        goto end;
    if (!BN_mod(plain, tmp, key->l, ctx))
        goto end;
    if (BN_cmp(plain,key->ld2)>0)
    {
        if(!BN_sub(plain, plain, key->l))
            goto end;
    }


    ret = 0;
end:
    if (ret)
    {
        printf("error\n");
    }
    BN_CTX_end(ctx);
    return ret;
}


int addTest_she(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const SHE_key *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encrypt_she(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (!BN_mod_add(result, enc, plain_enc, key->n, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        printf("error\n");
    }

    BN_CTX_end(ctx);
    return ret;
}

#endif






















