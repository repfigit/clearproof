/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Native C accelerator for BN254 scalar-field Poseidon permutation.
 *
 * Uses Montgomery arithmetic over the BN254 scalar field:
 *   p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *
 * All round constants and MDS matrices are supplied by Python from
 * poseidon_constants.json so the C library carries zero independent
 * cryptographic parameter tables and stays bit-exact with poseidon.py.
 *
 * ABI (32-byte little-endian canonical field elements < p):
 *   int clearproof_poseidon_abi_version(void);
 *   int clearproof_poseidon_load_constants(
 *       uint32_t t,
 *       uint32_t n_rounds_f,
 *       uint32_t n_rounds_p,
 *       const uint8_t *c_le32,   // (n_rounds_f + n_rounds_p) * t * 32 bytes, each < p
 *       const uint8_t *m_le32    // t * t * 32 bytes (row-major), each < p
 *   );
 *   int clearproof_poseidon_hash_cached(
 *       uint32_t t,
 *       const uint8_t *inputs_le32,  // (t - 1) * 32 bytes, each < p
 *       uint8_t *out_le32            // 32 bytes output < p
 *   );
 *   int clearproof_poseidon_hash(
 *       uint32_t t,
 *       uint32_t n_rounds_f,
 *       uint32_t n_rounds_p,
 *       const uint8_t *inputs_le32,   // (t - 1) * 32 bytes, each < p
 *       const uint8_t *c_le32,        // (n_rounds_f + n_rounds_p) * t * 32 bytes, each < p
 *       const uint8_t *m_le32,        // t * t * 32 bytes (row-major), each < p
 *       uint8_t *out_le32             // 32 bytes output < p
 *   );
 *
 * Returns 0 on success, non-zero on invalid arguments or out-of-range inputs.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CLEARPROOF_POSEIDON_ABI_VERSION 1
#define MAX_T 17
#define MAX_ROUNDS 256

typedef struct {
    uint64_t l[4];
} fr_t;

/* BN254 scalar field modulus p (little-endian 64-bit limbs). */
static const fr_t FR_MOD = {{
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
}};

/* R^2 mod p, where R = 2^256 (little-endian 64-bit limbs). */
static const fr_t FR_R2 = {{
    0x1bb8e645ae216da7ULL,
    0x53fe3ab1e35c59e3ULL,
    0x8c49833d53bb8085ULL,
    0x0216d0b17f4e44a5ULL
}};

/* -p^{-1} mod 2^64 */
static const uint64_t FR_INV = 0xc2e1f593efffffffULL;

typedef struct {
    int loaded;
    uint32_t n_rounds_f;
    uint32_t n_rounds_p;
    fr_t C[MAX_ROUNDS * MAX_T];
    fr_t M[MAX_T][MAX_T];
} cached_params_t;

static cached_params_t g_params[MAX_T + 1];

static inline uint64_t load_le64(const uint8_t *p) {
    return ((uint64_t)p[0])
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

static inline void store_le64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
    p[4] = (uint8_t)((v >> 32) & 0xffU);
    p[5] = (uint8_t)((v >> 40) & 0xffU);
    p[6] = (uint8_t)((v >> 48) & 0xffU);
    p[7] = (uint8_t)((v >> 56) & 0xffU);
}

static inline fr_t fr_from_bytes(const uint8_t *b) {
    fr_t r;
    r.l[0] = load_le64(b + 0);
    r.l[1] = load_le64(b + 8);
    r.l[2] = load_le64(b + 16);
    r.l[3] = load_le64(b + 24);
    return r;
}

static inline void fr_to_bytes(uint8_t *b, const fr_t *a) {
    store_le64(b + 0, a->l[0]);
    store_le64(b + 8, a->l[1]);
    store_le64(b + 16, a->l[2]);
    store_le64(b + 24, a->l[3]);
}

/* Returns 1 if a >= p, else 0. */
static inline int fr_gte_mod(const fr_t *a) {
    for (int i = 3; i >= 0; --i) {
        if (a->l[i] > FR_MOD.l[i]) {
            return 1;
        }
        if (a->l[i] < FR_MOD.l[i]) {
            return 0;
        }
    }
    return 1; /* equal to p */
}

/* Subtract p from a in place (assumes a >= p). */
static inline void fr_sub_mod(fr_t *a) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 ai = a->l[i];
        unsigned __int128 pi = (unsigned __int128)FR_MOD.l[i] + borrow;
        if (ai < pi) {
            a->l[i] = (uint64_t)((ai + ((unsigned __int128)1 << 64)) - pi);
            borrow = 1;
        } else {
            a->l[i] = (uint64_t)(ai - pi);
            borrow = 0;
        }
    }
}

/* Field addition: r = (a + b) mod p. Inputs in [0, p-1]. */
static inline fr_t fr_add(const fr_t *a, const fr_t *b) {
    fr_t r;
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 s = (unsigned __int128)a->l[i] + b->l[i] + carry;
        r.l[i] = (uint64_t)s;
        carry = s >> 64;
    }
    if (fr_gte_mod(&r)) {
        fr_sub_mod(&r);
    }
    return r;
}

/* CIOS Montgomery multiplication: r = a * b * R^{-1} mod p. */
static inline fr_t fr_mont_mul(const fr_t *a, const fr_t *b) {
    uint64_t t[5] = {0, 0, 0, 0, 0};

    for (int i = 0; i < 4; ++i) {
        unsigned __int128 carry = 0;
        unsigned __int128 ai = a->l[i];
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 prod = ai * b->l[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        unsigned __int128 sum = (unsigned __int128)t[4] + carry;
        t[4] = (uint64_t)sum;

        uint64_t m = t[0] * FR_INV;
        unsigned __int128 m128 = m;
        unsigned __int128 c2 = (m128 * FR_MOD.l[0] + t[0]) >> 64;
        for (int j = 1; j < 4; ++j) {
            unsigned __int128 prod = m128 * FR_MOD.l[j] + t[j] + c2;
            t[j - 1] = (uint64_t)prod;
            c2 = prod >> 64;
        }
        unsigned __int128 hi = (unsigned __int128)t[4] + c2;
        t[3] = (uint64_t)hi;
        t[4] = (uint64_t)(hi >> 64);
    }

    fr_t r = {{t[0], t[1], t[2], t[3]}};
    if (t[4] || fr_gte_mod(&r)) {
        fr_sub_mod(&r);
    }
    return r;
}

static inline fr_t fr_to_mont(const fr_t *a) {
    return fr_mont_mul(a, &FR_R2);
}

static inline fr_t fr_from_mont(const fr_t *a) {
    static const fr_t ONE = {{1ULL, 0ULL, 0ULL, 0ULL}};
    return fr_mont_mul(a, &ONE);
}

static inline fr_t fr_pow5_mont(const fr_t *a) {
    fr_t a2 = fr_mont_mul(a, a);
    fr_t a4 = fr_mont_mul(&a2, &a2);
    return fr_mont_mul(&a4, a);
}

static inline void poseidon_permute_mont(
    uint32_t t,
    uint32_t n_rounds_f,
    uint32_t n_rounds_p,
    fr_t *state,
    const fr_t *C_mont,
    const fr_t M_mont[MAX_T][MAX_T]
) {
    fr_t next_state[MAX_T];
    uint32_t total_rounds = n_rounds_f + n_rounds_p;
    uint32_t half_f = n_rounds_f / 2U;

    for (uint32_t r = 0; r < total_rounds; ++r) {
        size_t base = (size_t)r * t;
        for (uint32_t i = 0; i < t; ++i) {
            state[i] = fr_add(&state[i], &C_mont[base + i]);
        }

        if (r < half_f || r >= half_f + n_rounds_p) {
            for (uint32_t i = 0; i < t; ++i) {
                state[i] = fr_pow5_mont(&state[i]);
            }
        } else {
            state[0] = fr_pow5_mont(&state[0]);
        }

        for (uint32_t i = 0; i < t; ++i) {
            fr_t acc = {{0ULL, 0ULL, 0ULL, 0ULL}};
            for (uint32_t j = 0; j < t; ++j) {
                fr_t prod = fr_mont_mul(&M_mont[i][j], &state[j]);
                acc = fr_add(&acc, &prod);
            }
            next_state[i] = acc;
        }
        for (uint32_t i = 0; i < t; ++i) {
            state[i] = next_state[i];
        }
    }
}

int clearproof_poseidon_abi_version(void) {
    return CLEARPROOF_POSEIDON_ABI_VERSION;
}

int clearproof_poseidon_load_constants(
    uint32_t t,
    uint32_t n_rounds_f,
    uint32_t n_rounds_p,
    const uint8_t *c_le32,
    const uint8_t *m_le32
) {
    if (t < 2 || t > MAX_T) {
        return -1;
    }
    if (n_rounds_f == 0 || (n_rounds_f & 1U) != 0 || n_rounds_p == 0 || n_rounds_f + n_rounds_p > MAX_ROUNDS) {
        return -2;
    }
    if (!c_le32 || !m_le32) {
        return -3;
    }

    cached_params_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.n_rounds_f = n_rounds_f;
    tmp.n_rounds_p = n_rounds_p;

    size_t total_c = (size_t)(n_rounds_f + n_rounds_p) * t;
    for (size_t idx = 0; idx < total_c; ++idx) {
        fr_t v = fr_from_bytes(c_le32 + idx * 32U);
        if (fr_gte_mod(&v)) {
            return -6;
        }
        tmp.C[idx] = fr_to_mont(&v);
    }

    for (uint32_t i = 0; i < t; ++i) {
        for (uint32_t j = 0; j < t; ++j) {
            fr_t v = fr_from_bytes(m_le32 + ((size_t)i * t + j) * 32U);
            if (fr_gte_mod(&v)) {
                return -5;
            }
            tmp.M[i][j] = fr_to_mont(&v);
        }
    }

    tmp.loaded = 1;
    g_params[t] = tmp;
    return 0;
}

int clearproof_poseidon_hash_cached(
    uint32_t t,
    const uint8_t *inputs_le32,
    uint8_t *out_le32
) {
    if (t < 2 || t > MAX_T) {
        return -1;
    }
    if (!inputs_le32 || !out_le32) {
        return -3;
    }
    const cached_params_t *p = &g_params[t];
    if (!p->loaded) {
        return -7;
    }

    fr_t state[MAX_T];
    memset(&state[0], 0, sizeof(fr_t));
    for (uint32_t i = 1; i < t; ++i) {
        fr_t v = fr_from_bytes(inputs_le32 + (size_t)(i - 1) * 32U);
        if (fr_gte_mod(&v)) {
            return -4;
        }
        state[i] = fr_to_mont(&v);
    }

    poseidon_permute_mont(t, p->n_rounds_f, p->n_rounds_p, state, p->C, p->M);

    fr_t result = fr_from_mont(&state[0]);
    fr_to_bytes(out_le32, &result);
    return 0;
}

int clearproof_poseidon_hash(
    uint32_t t,
    uint32_t n_rounds_f,
    uint32_t n_rounds_p,
    const uint8_t *inputs_le32,
    const uint8_t *c_le32,
    const uint8_t *m_le32,
    uint8_t *out_le32
) {
    if (t < 2 || t > MAX_T) {
        return -1;
    }
    if (n_rounds_f == 0 || (n_rounds_f & 1U) != 0 || n_rounds_p == 0 || n_rounds_f + n_rounds_p > MAX_ROUNDS) {
        return -2;
    }
    if (!inputs_le32 || !c_le32 || !m_le32 || !out_le32) {
        return -3;
    }

    fr_t state[MAX_T];
    fr_t C_mont[MAX_ROUNDS * MAX_T];
    fr_t M_mont[MAX_T][MAX_T];

    memset(&state[0], 0, sizeof(fr_t));
    for (uint32_t i = 1; i < t; ++i) {
        fr_t v = fr_from_bytes(inputs_le32 + (size_t)(i - 1) * 32U);
        if (fr_gte_mod(&v)) {
            return -4;
        }
        state[i] = fr_to_mont(&v);
    }

    size_t total_c = (size_t)(n_rounds_f + n_rounds_p) * t;
    for (size_t idx = 0; idx < total_c; ++idx) {
        fr_t v = fr_from_bytes(c_le32 + idx * 32U);
        if (fr_gte_mod(&v)) {
            return -6;
        }
        C_mont[idx] = fr_to_mont(&v);
    }

    for (uint32_t i = 0; i < t; ++i) {
        for (uint32_t j = 0; j < t; ++j) {
            fr_t v = fr_from_bytes(m_le32 + ((size_t)i * t + j) * 32U);
            if (fr_gte_mod(&v)) {
                return -5;
            }
            M_mont[i][j] = fr_to_mont(&v);
        }
    }

    poseidon_permute_mont(t, n_rounds_f, n_rounds_p, state, C_mont, M_mont);

    fr_t result = fr_from_mont(&state[0]);
    fr_to_bytes(out_le32, &result);
    return 0;
}
