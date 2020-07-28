/*
 * Author Chen Gao
 * Created at 01 Nov 2018
 *
 * This file shamir.h is part of ccs_engine.
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

#ifndef CCS_ENGINE_SHAMIR_H
#define CCS_ENGINE_SHAMIR_H

#include <stdlib.h>
#include <openssl/bn.h>

typedef struct shamir_key_share_s shm_key_share_t;

/**
 * generate shamir key shares
 * @param r
 *      generated key share list
 * @param security_lv
 *      desired key length in bits
 * @param min_share
 *      minimum key share needed to recover secret
 * @param max_share
 *      total number of key share will be generated
 * @param secret
 *      if provided, keygen will use this secret to generate key share
 * @param secret_len
 *      length of [secret] in byte
 * @param base
 *      base of key share, 2 for bin, 16 for hex, etc.
 * @return
 *      see error code defines in shamir.h
 */
int
shm_keygen(shm_key_share_t *r,
           int security_lv,
           int min_share,
           int max_share,
           uint8_t *secret,
           int secret_len,
           int base);

/**
 * recover secret from given key share
 * @param r
 *      secret in binary form
 * @param r_len
 *      length of [secret]
 * @param ks
 *      key share list
 * @param min_share
 *      minimum key share required
 * @return
 *      see error def in shamir.h
 */
int
shm_recover_secret(uint8_t *r,
                   size_t *r_len,
                   shm_key_share_t *ks,
                   int min_share);

/**
 * create more key share for existing secret key
 * @param r
 *      new key shares
 * @param ks
 *      existing key shares
 * @param min
 *      minimum key share required
 * @param num
 *      num of new key shares
 * @param base
 *      encoding for key share
 * @return
 *      see error def in shamir.h
 * @note
 *      only call this when you have enough existing key share
 */
int
shm_create_more_key_share(shm_key_share_t *r,
                          shm_key_share_t *ks,
                          int min,
                          int num,
                          int base);

/**
 * free key share list
 * @note
 *      must be called if shm_key_share_t_new was called.
 */
void
shm_cleanup(shm_key_share_t *ks);

#define THLD_MAX_STRING_LENGTH      1000

#define THLD_OK                      1
#define ERR_THLD                     0
#define ERR_THLD_MALLOC_ERROR       -1
#define ERR_THLD_KEY_LENGTH         -2
#define ERR_THLD_SHARE_NUM          -3
#define ERR_THLD_BASE_ERROR         -4
#define ERR_THLD_NULL_POINTER       -5
#define ERR_THLD_BN_ERROR           -6
#define ERR_THLD_BN_RANGE           -7
#define ERR_THLD_MEM_LEAK           -8

#define THLD_BINARY                 2
#define THLD_HEX                    16
#define THLD_BASE64                 64

/**
 * check if key length is supported
 * @param len
 *      length of secret key in bits
 * @return
 *      0 if not supported, 128|256...if supported
 */
int
shm_security_level(int len);

/**
 * check if base is supported.
 * 2 for bin, 16 for hex, etc.
 * @param base
 * @return
 *      base if supported, base error code if not.
 */
int
shm_check_base(int base);

/**
 * allocate space for a new key share
 * @return
 *      pointer to an empty key share, NULL on error
 */
shm_key_share_t *
shm_key_share_new();

/**
 * set base of key share
 * @param ks
 * @param base
 *      2 for bin, 16 for hex, etc.
 * @return
 *      see error code define in shamir.h
 */
int
shm_key_share_set_base(shm_key_share_t *ks, int base);

/**
 * get base stored in key share
 */
int
shm_key_share_base(shm_key_share_t *ks);

/**
 * set number of key share required
 */
int
shm_key_share_set_threshold(shm_key_share_t *ks, int t);

/**
 * get number of key share needed to recover secret
 */
int
shm_key_share_threshold(shm_key_share_t *ks);

/**
 * get next element in key share list
 */
shm_key_share_t *
shm_key_share_next(shm_key_share_t *ks);

/**
 * set next element to key share list
 * current node should not have linked to any next element
 * @return
 *      see error code define in shamir.h
 */
int
shm_key_share_set_next(shm_key_share_t *ks, shm_key_share_t *next);

/**
 * get length of x string from key share
 * @param ks
 *      key share
 * @return
 *      length of x
 */
int
shm_key_share_x_len(shm_key_share_t *ks);

/**
 * @see threshold#shm_key_share_x_len
 */
int
shm_key_share_y_len(shm_key_share_t *ks);

/**
 * @see threshold#shm_key_share_x_len
 */
int
shm_key_share_p_len(shm_key_share_t *ks);

/**
 * set x encode string to key share
 * @param ks
 *      key share
 * @param x
 *      x coordinate string
 * @param x_len
 *      length of [x]
 * @param base
 *      x string encoding
 * @return
 *      see error def in shamir.h
 */
int
shm_key_share_set_x(shm_key_share_t *ks, uint8_t *x, size_t x_len, int base);

/**
 * @see threshold#shm_key_share_set_x
 */
int
shm_key_share_set_y(shm_key_share_t *ks, uint8_t *y, size_t y_len, int base);

/**
 * @see threshold#shm_key_share_set_x
 */
int
shm_key_share_set_p(shm_key_share_t *ks, uint8_t *p, size_t p_len, int base);

/**
 * get x coordinate in string
 * @return
 *      x string
 */
uint8_t *
shm_key_share_x(shm_key_share_t *ks);

/**
 * @see threshold#shm_key_share_x
 */
uint8_t *
shm_key_share_y(shm_key_share_t *ks);

/**
 * @see threshold#shm_key_share_x
 */
uint8_t *
shm_key_share_p(shm_key_share_t *ks);

// ============== REMOVE ================
#if 0
int
shm_key_share_reconstruct(BIGNUM *r[], shm_key_share_t *ks, int min);

int
shm_key_share_evaluate(BIGNUM *r,
                       BIGNUM *rx,
                       BIGNUM *x[],
                       BIGNUM *tb[],
                       BIGNUM *field,
                       int tb_size);
#endif
#endif //CCS_ENGINE_SHAMIR_H

