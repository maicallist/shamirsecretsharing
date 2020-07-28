/*
 * Author Chen Gao
 * Created at 01 Nov 2018
 *
 * This file shamir.c is part of ccs_engine.
 *
 * ccs_engine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ccs_engine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ccs_engine.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdbool.h>
#include <memory.h>

#include "shamir.h"

typedef struct shamir_polynomial_s shm_poly_t;

static void *
(*const volatile memset_ptr)(void *, int, size_t) = memset;

/**
 * generate new sets of key share
 * @param r
 *      returned key share list,
 *      first node [r] must be allocated before calling this function.
 * @param security_level
 *      key length of secret
 * @param num
 *      number of key share to be generated
 * @param p_head
 *      polynomial used to generate key share
 * @param field
 *      finite field size
 * @param base
 *      binary, hex, etc.
 * @return
 *      see error def in shamir.h
 */
static int
shm_key_share_init(shm_key_share_t *r,
                   int security_level,
                   int num,
                   shm_poly_t *p_head,
                   BIGNUM *field,
                   int base);
/**
 * reconstruct newton's diff table for the polynomial
 * @param r
 *      diff table
 * @param rx
 *      x coordinate used to generate diff table
 * @param rp
 *      finite field
 * @param ks
 *      key share
 * @param min
 *      minimum share required
 * @return
 *      see error def in shamir.h
 */
static int
shm_key_share_reconstruct(BIGNUM *r[],
                          BIGNUM *rx[],
                          BIGNUM *rp,
                          shm_key_share_t *ks,
                          int min);

/**
 * evaluate polynomial using Horner's rule
 * @param r
 *      y coordinate for [rx] on polynomial [tb] baseds on divided diff
 * @param rx
 *      x coordinate on polynomial
 * @param x
 *      list of x coordinate matching [tb] difference
 * @param tb
 *      difference table generated from [x] list
 * @param field
 *      finite field
 * @param tb_size
 *      number of element in [tb]
 * @return
 *      see error def in shamir.h
 */
static int
shm_key_share_evaluate(BIGNUM *r,
                       BIGNUM *rx,
                       BIGNUM *x[],
                       BIGNUM *tb[],
                       BIGNUM *field,
                       int tb_size);

struct shamir_polynomial_s
{
    shm_poly_t *next;
    BIGNUM *cof;        /* coefficient */
    int degree;         /* power */
};

struct shamir_key_share_s
{
    shm_key_share_t *next;
    uint8_t *x;
    uint8_t *y;
    uint8_t *p;         /* finite field range */
    int x_len;
    int y_len;
    int p_len;
    int base;
    int min;            /* minimum share to recover secret */
};

#define DEBUG_PRIME         1613
int test_cof[4] = {1234, 166, 94, 0};

/**
 * write bignum to string
 * @param ks
 *      key share
 * @param x
 *      x coordinate of key share
 * @param y
 *      y coordinate of key share
 * @param p
 *      finite field
 * @return
 *      see error codes in shamir.h
 */
static int
shm_bn2base(shm_key_share_t *ks, BIGNUM *x, BIGNUM *y, BIGNUM *p, int base)
{
    switch (base)
    {
        case 0:
        case THLD_BINARY:
            if (NULL == (ks->x = OPENSSL_secure_malloc(BN_num_bytes(x))))
                return ERR_THLD_MALLOC_ERROR;
            if (NULL == (ks->y = OPENSSL_secure_malloc(BN_num_bytes(y))))
                return ERR_THLD_MALLOC_ERROR;
            if (NULL == (ks->p = OPENSSL_secure_malloc(BN_num_bytes(p))))
                return ERR_THLD_MALLOC_ERROR;
            ks->x_len = BN_num_bytes(x);
            ks->y_len = BN_num_bytes(y);
            ks->p_len = BN_num_bytes(p);
            if (BN_bn2bin(x, ks->x) < 1)
                return ERR_THLD_BN_ERROR;
            if (BN_bn2bin(y, ks->y) < 1)
                return ERR_THLD_BN_ERROR;
            if (BN_bn2bin(p, ks->p) < 1)
                return ERR_THLD_BN_ERROR;
            break;
        case THLD_HEX:
            if (NULL == (ks->x = (uint8_t *) BN_bn2hex(x)))
                return ERR_THLD_BN_ERROR;
            if (NULL == (ks->y = (uint8_t *) BN_bn2hex(y)))
                return ERR_THLD_BN_ERROR;
            if (NULL == (ks->p = (uint8_t *) BN_bn2hex(p)))
                return ERR_THLD_BN_ERROR;
            ks->x_len = (int) strnlen((char *) ks->x, THLD_MAX_STRING_LENGTH);
            ks->y_len = (int) strnlen((char *) ks->y, THLD_MAX_STRING_LENGTH);
            ks->p_len = (int) strnlen((char *) ks->p, THLD_MAX_STRING_LENGTH);
            break;
            //case THLD_BASE64:
        default:return ERR_THLD_BASE_ERROR;
    }
    return THLD_OK;
}

/**
 * convert string to BIGNUM
 * @param r
 *      BN result
 * @param str
 *      stream to be converted to BN
 * @param str_len
 *      length of [str] in byte
 * @param base
 *      representation of [str], binary, hex, etc.
 * @return
 *      see error def in shamir.h
 */
static int
shm_base2bn(BIGNUM **r, uint8_t *str, int str_len, int base)
{
    switch (base)
    {
        case 0:
        case 2:
            if (NULL == BN_bin2bn(str, str_len, *r))
                return ERR_THLD_BN_ERROR;
            break;
        case 16:;
            if (str_len != BN_hex2bn(r, (char *) str))
                return ERR_THLD_BN_ERROR;
            break;
            //case 64:
        default:memset(r, 0, sizeof(BN_num_bytes(*r)));
            return ERR_THLD_BASE_ERROR;
    }

    return THLD_OK;
}

int
shm_security_level(int len)
{
    switch (len)
    {
        case 0: len = 128;
        case 128:
            //case 192:
        case 256:
            //case 384:
            //case 512:
            return len;
        default:return 0;
    }
}

int
shm_check_base(int base)
{
    switch (base)
    {
        case 0: base = THLD_BINARY;
        case THLD_BINARY:
        case THLD_HEX:
            //case THLD_BASE64:
            return base;
        default: return ERR_THLD_BASE_ERROR;
    }
}

int
shm_keygen(shm_key_share_t *r,
           int security_lv,
           int min_share,
           int max_share,
           uint8_t *secret,
           int secret_len,
           int base)
{
    #if DEBUG
    if (min_share != 3)
        return -999;
    #endif

    int ret = ERR_THLD_MALLOC_ERROR;

    if (!r)
        return ERR_THLD_NULL_POINTER;

    if (min_share < 1)
        return ERR_THLD_SHARE_NUM;

    if (min_share > max_share)
        return ERR_THLD_SHARE_NUM;

    if (secret)
    {
        if (!secret_len)
            return ERR_THLD_KEY_LENGTH;

        #ifndef DEBUG
        if (!shm_security_level(secret_len * 8))
            return ERR_THLD_KEY_LENGTH;
        // BN_RAND_TOP_ONE
        if ((secret[0] & 0x80) == 0)
            return ERR_THLD_BN_RANGE;
        #endif
    }

    BIGNUM *field;
    shm_poly_t *p_head = NULL;

    if (NULL == (field = BN_secure_new()))
        goto err;

    #if DEBUG
    if (1 != BN_set_word(field, DEBUG_PRIME))
    {
        ret = ERR_THLD_BN_ERROR;
        goto err;
    }
    #else
    if (1
        != BN_generate_prime_ex(field, security_lv + 1, true, NULL, NULL, NULL))
    {
        ret = ERR_THLD_BN_ERROR;
        goto err;
    }
    #endif

    shm_poly_t *node;
    for (int i = min_share - 1; i > -1; --i)
    {
        if (NULL == (node = OPENSSL_secure_zalloc(sizeof(shm_poly_t))))
            goto err;
        node->next = p_head;
        p_head = node;

        node->degree = i;
        if (NULL == (node->cof = BN_secure_new()))
            goto err;
        #if DEBUG
        if (1 != BN_set_word(node->cof, test_cof[i]))
            goto err;
        #else
        if (1 != BN_priv_rand(node->cof,
                              security_lv,
                              BN_RAND_TOP_ONE,
                              BN_RAND_BOTTOM_ANY))
        {
            ret = ERR_THLD_BN_ERROR;
            goto err;
        }
        #endif
    }

    if (secret)
    {
        if (THLD_OK != shm_base2bn(&p_head->cof, secret, secret_len, base))
        {
            ret = ERR_THLD_BN_ERROR;
            goto err;
        }
        if (1 != BN_cmp(field, p_head->cof))
        {
            ret = ERR_THLD_BN_RANGE;
            goto err;
        }
    }

    ret = shm_key_share_init(r, security_lv, max_share, p_head, field, base);

    err:

    if (field)
        BN_clear_free(field);

    if (p_head)
    {
        shm_poly_t **pp = &p_head;
        shm_poly_t *n = p_head;

        while (n)
        {
            *pp = n->next;
            if (n->cof)
                BN_clear_free(n->cof);
            OPENSSL_secure_clear_free(n, sizeof(shm_poly_t));
            n = p_head;
        }
    }

    return ret;
}

static int
shm_key_share_init(shm_key_share_t *r,
                   int security_level,
                   int num,
                   shm_poly_t *p_head,
                   BIGNUM *field,
                   int base)
{
    BIGNUM *x, *y, *d, *t;
    BN_CTX *ctx;
    shm_key_share_t *ks_head = NULL;

    int ret = ERR_THLD_BN_ERROR;

    if (!p_head)
        return ERR_THLD_NULL_POINTER;

    if (!field)
        return ERR_THLD_NULL_POINTER;

    shm_poly_t *p_node;
    shm_key_share_t *ks_node;

    if (NULL == (ctx = BN_CTX_secure_new()))
        return ERR_THLD_MALLOC_ERROR;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    d = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);

    if (!t)
        goto err;

    for (int i = 0; i < num; ++i)
    {
        if (1 != BN_zero(y))
            goto err;

        #if DEBUG
        if (1 != BN_set_word(x, (unsigned)i + 1))
            goto err;
        #else
        if (0 == BN_priv_rand(x,
                              security_level,
                              BN_RAND_TOP_ANY,
                              BN_RAND_BOTTOM_ANY))
            goto err;
        #endif

        p_node = p_head;
        while (p_node)
        {
            if (1 != BN_set_word(d, (unsigned) p_node->degree))
                goto err;

            if (1 != BN_mod_exp(t, x, d, field, ctx))
                goto err;

            if (1 != BN_mod_mul(t, t, p_node->cof, field, ctx))
                goto err;

            if (1 != BN_mod_add(y, y, t, field, ctx))
                goto err;

            p_node = p_node->next;
        } // end of while

        // setup return
        if (NULL == (ks_node = OPENSSL_secure_zalloc(sizeof(shm_key_share_t))))
        {
            ret = ERR_THLD_MALLOC_ERROR;
            goto err;
        }

        ks_node->next = ks_head;
        ks_head = ks_node;

        ks_node->base = base;
        if (1 != (ret = shm_bn2base(ks_node, x, y, field, base)))
            return ret;
        ret = ERR_THLD_BN_ERROR;

    } // end of for

    memcpy(r, ks_head, sizeof(shm_key_share_t));
    OPENSSL_secure_clear_free(ks_head, sizeof(shm_key_share_t));
    ret = THLD_OK;

    err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

static int
shm_key_share_reconstruct(BIGNUM *r[],
                          BIGNUM *rx[],
                          BIGNUM *rp,
                          shm_key_share_t *ks,
                          int min)
{
    shm_key_share_t *pks;
    BN_CTX *ctx;
    BIGNUM *x[min];
    BIGNUM *y[min];
    BIGNUM *p[min];

    BIGNUM *d;
    int ret;

    //newtons divided diff table
    BIGNUM *diff[min];

    if (NULL == (ctx = BN_CTX_new()))
        return ERR_THLD_MALLOC_ERROR;
    BN_CTX_start(ctx);

    pks = ks;
    for (int i = 0; i < min; ++i)
    {
        if (!pks)
        {
            ret = ERR_THLD_SHARE_NUM;
            goto err;
        }

        /* no need to check, they are alloc by reconstruct & more_share
         * which are already checked through BN_CTX_get */
        #if 0
        if (!r[i])
        {
            ret = ERR_THLD_MALLOC_ERROR;
            goto err;
        }
        #endif

        x[i] = BN_CTX_get(ctx);
        if (THLD_OK
            != (ret = shm_base2bn(&x[i], pks->x, pks->x_len, pks->base)))
            goto err;
        y[i] = BN_CTX_get(ctx);
        if (THLD_OK
            != (ret = shm_base2bn(&y[i], pks->y, pks->y_len, pks->base)))
            goto err;
        p[i] = BN_CTX_get(ctx);
        if (THLD_OK
            != (ret = shm_base2bn(&p[i], pks->p, pks->p_len, pks->base)))
            goto err;

        pks = pks->next;

        // Uber
        // not using dup, release with bn ctx
        diff[i] = BN_CTX_get(ctx);
        if (NULL == (BN_copy(diff[i], y[i])))
        {
            ret = ERR_THLD_BN_ERROR;
            goto err;
        }
    }

    ret = ERR_THLD_BN_ERROR;

    // lousy check if all shares are from the same field
    for (int i = 1; i < min; ++i)
    {
        if (0 != BN_cmp(p[0], p[i]))
        {
            ret = ERR_THLD_BN_RANGE;
            goto err;
        }
    }

    d = BN_CTX_get(ctx);
    if (!d)
        goto err;

    if (NULL == (BN_copy(r[0], diff[0])))
        goto err;

    for (int i = 1; i < min; ++i)
    {
        for (int j = 0; j < min - i; ++j)
        {
            if (1 != BN_mod_sub(d, x[i + j], x[j], p[0], ctx))
                goto err;
            if (1 != BN_mod_sub(diff[j], diff[j + 1], diff[j], p[0], ctx))
                goto err;
            if (NULL == BN_mod_inverse(d, d, p[0], ctx))
                goto err;
            if (1 != BN_mod_mul(diff[j], diff[j], d, p[0], ctx))
                goto err;
        }
        if (NULL == (BN_copy(r[i], diff[0])))
            goto err;
    }

    if (NULL == (BN_copy(rp, p[0])))
        goto err;
    for (int i = 0; i < min; ++i)
    {
        if (NULL == (BN_copy(rx[i], x[i])))
            goto err;
    }

    ret = THLD_OK;
    err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

static int
shm_key_share_evaluate(BIGNUM *r,
                       BIGNUM *rx,
                       BIGNUM *x[],
                       BIGNUM *tb[],
                       BIGNUM *field,
                       int tb_size)
{
    if (!r)
        return ERR_THLD_NULL_POINTER;
    if (!rx)
        return ERR_THLD_NULL_POINTER;
    if (!x)
        return ERR_THLD_NULL_POINTER;
    if (!tb)
        return ERR_THLD_NULL_POINTER;
    if (!field)
        return ERR_THLD_NULL_POINTER;

    BIGNUM *tmp;
    BN_CTX *ctx;
    int ret = ERR_THLD_BN_ERROR;

    if (NULL == (ctx = BN_CTX_new()))
        return ERR_THLD_MALLOC_ERROR;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (!tmp)
        goto err;

    if (NULL == BN_copy(r, tb[tb_size - 1]))
        goto err;
    /*
     * explanation of [tb_size - 2]
     *
     * according to Horner's rules
     * Pn(x) = f0 + f1(x - x[1]) + ... + fn(x-x[0])..(x-x[n-1])
     *
     * difference table holds f0 to fn, total n + 1
     *
     * for k = n - 1 is equivalent to tb_size - 2
     */
    for (int i = tb_size - 2; i >= 0; --i)
    {
        if (1 != BN_sub(tmp, rx, x[i]))
            goto err;
        if (1 != BN_mod_mul(r, r, tmp, field, ctx))
            goto err;
        if (1 != BN_mod_add(r, r, tb[i], field, ctx))
            goto err;
    }

    ret = THLD_OK;

    err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

static BIGNUM *y = NULL;

int
shm_recover_secret(uint8_t *r,
                   size_t *r_len,
                   shm_key_share_t *ks,
                   int min_share)
{
    if (!r_len)
        return ERR_THLD_NULL_POINTER;
    // ks is tested in reconstruct.

    int ret = ERR_THLD_BN_ERROR;
    if (r)
    {
        if (!y)
            return ERR_THLD_NULL_POINTER;

        if (BN_bn2bin(y, r) < 1)
            return ERR_THLD_BN_ERROR;

        return THLD_OK;
    }

    BIGNUM *tb[min_share];
    BIGNUM *tbx[min_share];
    BIGNUM *rx, *rp;

    BN_CTX *ctx;
    if (NULL == (ctx = BN_CTX_new()))
        return ERR_THLD_MALLOC_ERROR;
    BN_CTX_start(ctx);

    for (int i = 0; i < min_share; ++i)
    {
        tb[i] = BN_CTX_get(ctx);
        tbx[i] = BN_CTX_get(ctx);
    }
    rp = BN_CTX_get(ctx);
    rx = BN_CTX_get(ctx);

    if (!rx)
        goto err;

    if (!y)
    {
        if (NULL == (y = BN_secure_new()))
            goto err;
    }

    if (THLD_OK
        != (ret = shm_key_share_reconstruct(tb, tbx, rp, ks, min_share)))
        goto err;

    if (1 != BN_set_word(rx, 0))
        goto err;

    if (THLD_OK
        != (ret = shm_key_share_evaluate(y, rx, tbx, tb, rp, min_share)))
        goto err;

    *r_len = (size_t) BN_num_bytes(y);

    ret = THLD_OK;
    err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

int
shm_create_more_key_share(shm_key_share_t *r,
                          shm_key_share_t *ks,
                          int min,
                          int num,
                          int base)
{
    if (!r)
        return ERR_THLD_NULL_POINTER;
    if (num < 1)
        return ERR_THLD_SHARE_NUM;
    if (!ks)
        return ERR_THLD_NULL_POINTER;

    int ret = ERR_THLD_BN_ERROR;
    BIGNUM *tb[min];
    BIGNUM *rx[min];
    BIGNUM *x, *y;
    BIGNUM *rp;

    BN_CTX *ctx;
    if (NULL == (ctx = BN_CTX_new()))
        return ERR_THLD_MALLOC_ERROR;
    BN_CTX_start(ctx);

    for (int i = 0; i < min; ++i)
    {
        rx[i] = BN_CTX_get(ctx);
        tb[i] = BN_CTX_get(ctx);
    }
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    rp = BN_CTX_get(ctx);

    if (!rp)
        goto err;

    if (THLD_OK != (ret = shm_key_share_reconstruct(tb, rx, rp, ks, min)))
        goto err;

    shm_key_share_t *head = NULL;
    shm_key_share_t *n;
    for (int i = 0; i < num; ++i)
    {
        #if DEBUG
        if (1 != BN_set_word(x, (unsigned long) (rand() % 7)))
            goto err;
        #else
        if (1 != BN_priv_rand(x,
                              BN_num_bits(rp) - 1,
                              BN_RAND_TOP_ONE,
                              BN_RAND_BOTTOM_ANY))
            goto err;
        #endif

        if (THLD_OK != (ret = shm_key_share_evaluate(y, x, rx, tb, rp, min)))
            goto err;

        if (NULL == (n = OPENSSL_secure_zalloc(sizeof(shm_key_share_t))))
        {
            ret = ERR_THLD_MALLOC_ERROR;
            goto err;
        }
        n->next = head;
        head = n;

        n->base = base;
        if (THLD_OK != (ret = shm_bn2base(n, x, y, rp, base)))
            goto err;
    }

    memcpy(r, head, sizeof(shm_key_share_t));
    OPENSSL_secure_clear_free(head, sizeof(shm_key_share_t));

    ret = THLD_OK;
    err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

void
shm_cleanup(shm_key_share_t *ks)
{
    if (!ks)
        return;

    shm_key_share_t **pp = &ks;
    shm_key_share_t *n = ks;

    while (n)
    {
        *pp = n->next;

        if (n->x)
            OPENSSL_secure_clear_free(n->x, (size_t) n->x_len);
        if (n->y)
            OPENSSL_secure_clear_free(n->y, (size_t) n->y_len);
        if (n->p)
            OPENSSL_secure_clear_free(n->p, (size_t) n->p_len);
        OPENSSL_secure_clear_free(n, sizeof(shm_key_share_t));

        n = ks;
    }

    if (y)
    {
        BN_clear_free(y);
        y = NULL;
    }
}

//==============================================================================

shm_key_share_t *
shm_key_share_new()
{
    return OPENSSL_secure_zalloc(sizeof(shm_key_share_t));
}

int
shm_key_share_set_base(shm_key_share_t *ks, int base)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    base = shm_check_base(base);
    if (base == ERR_THLD_BASE_ERROR)
        return base;
    ks->base = base;
    return THLD_OK;
}

int
shm_key_share_base(shm_key_share_t *ks)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    return ks->base;
}

int
shm_key_share_set_threshold(shm_key_share_t *ks, int t)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    ks->min = t;
    return THLD_OK;
}

int
shm_key_share_threshold(shm_key_share_t *ks)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    return ks->min;
}

shm_key_share_t *
shm_key_share_next(shm_key_share_t *ks)
{
    if (!ks)
        return NULL;
    return ks->next;
}

int
shm_key_share_set_next(shm_key_share_t *ks, shm_key_share_t *next)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    if (ks->next)
        return ERR_THLD_MEM_LEAK;
    ks->next = next;
    return THLD_OK;
}

int
shm_key_share_x_len(shm_key_share_t *ks)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    return ks->x_len;
}

int
shm_key_share_y_len(shm_key_share_t *ks)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    return ks->y_len;
}

int
shm_key_share_p_len(shm_key_share_t *ks)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;
    return ks->p_len;
}

int
shm_key_share_set_x(shm_key_share_t *ks, uint8_t *x, size_t x_len, int base)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;

    size_t n;
    switch (base)
    {
        case 0:
        case 2: n = x_len;
            break;
        case 16: n = x_len + 1;
            break;
        default:return ERR_THLD_BASE_ERROR;
    }
    if (NULL == (ks->x = OPENSSL_secure_zalloc(n)))
        return ERR_THLD_MALLOC_ERROR;
    memcpy(ks->x, x, x_len);

    ks->x_len = (int) n;
    ks->base = base;

    return THLD_OK;
}

int
shm_key_share_set_y(shm_key_share_t *ks, uint8_t *y, size_t y_len, int base)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;

    size_t n;
    switch (base)
    {
        case 0:
        case 2: n = y_len;
            break;
        case 16: n = y_len + 1;
            break;
        default:return ERR_THLD_BASE_ERROR;
    }
    if (NULL == (ks->y = OPENSSL_secure_zalloc(n)))
        return ERR_THLD_MALLOC_ERROR;
    memcpy(ks->y, y, y_len);

    ks->y_len = (int) n;
    ks->base = base;

    return THLD_OK;
}

int
shm_key_share_set_p(shm_key_share_t *ks, uint8_t *p, size_t p_len, int base)
{
    if (!ks)
        return ERR_THLD_NULL_POINTER;

    size_t n;
    switch (base)
    {
        case 0:
        case 2: n = p_len;
            break;
        case 16: n = p_len + 1;
            break;
        default:return ERR_THLD_BASE_ERROR;
    }
    if (NULL == (ks->p = OPENSSL_secure_zalloc(n)))
        return ERR_THLD_MALLOC_ERROR;
    memcpy(ks->p, p, p_len);

    ks->p_len = (int) n;
    ks->base = base;

    return THLD_OK;
}

uint8_t *
shm_key_share_x(shm_key_share_t *ks)
{
    if (!ks)
        return NULL;
    return ks->x;
}

uint8_t *
shm_key_share_y(shm_key_share_t *ks)
{
    if (!ks)
        return NULL;
    return ks->y;
}

uint8_t *
shm_key_share_p(shm_key_share_t *ks)
{
    if (!ks)
        return NULL;
    return ks->p;
}
