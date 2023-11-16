/*
 * Copyright(c) 2020-2023 All rights reserved by Heekuck Oh.
 * 이 프로그램은 한양대학교 ERICA 컴퓨터학부 학생을 위한 교육용으로 제작되었다.
 * 한양대학교 ERICA 학생이 아닌 자는 이 프로그램을 수정하거나 배포할 수 없다.
 * 프로그램을 수정할 경우 날짜, 학과, 학번, 이름, 수정 내용을 기록한다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <gmp.h>
#include <stdio.h>
#include <string.h>

#include "pkcs.h"
#include "sha2.h"

typedef void (*HashFunction)(const unsigned char *, unsigned int,
                             unsigned char *);

HashFunction sha2_functions[] = {sha224, sha256,     sha384,
                                 sha512, sha512_224, sha512_256};
int findSHA[] = {SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE,
                 SHA512_DIGEST_SIZE, SHA224_DIGEST_SIZE, SHA256_DIGEST_SIZE};

/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode) {
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;

    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE / 2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE / 2 - 1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE / 2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE / 2 - 1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        /*
         * If we select e = 65537, it should be relatively prime to Lambda(n)
         */
        if (mode == 0) {
            mpz_sub_ui(p, p, 1);
            if (mpz_gcd_ui(gcd, p, 65537) != 1)
                continue;
            else
                mpz_add_ui(p, p, 1);
            mpz_sub_ui(q, q, 1);
            if (mpz_gcd_ui(gcd, q, 65537) != 1)
                continue;
            else
                mpz_add_ui(q, q, 1);
        }
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE - 1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else
        do {
            mpz_urandomb(e, state, RSAKEYSIZE);
            mpz_gcd(gcd, e, lambda);
        } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE / 8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE / 8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE / 8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for
 * success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n) {
    mpz_t m, k, n;

    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE / 8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE / 8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE / 8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE / 8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}
// len = 입력 길이 (출력은 고정)
void hash(const unsigned char *message, unsigned int len, unsigned char *digest,
          int sha2_ndx) {
    sha2_functions[sha2_ndx](message, len, digest);
}
unsigned char *I2OSP(unsigned long x, int xLen) {
    if (xLen < 0 || xLen > 4) {
        return NULL;
    }

    unsigned char *os = (unsigned char *)malloc(xLen);
    if (os == NULL) {
        return NULL;
    }

    for (int i = 0; i < xLen; i++) {
        os[i] = (x >> (8 * (xLen - 1 - i))) & 0xFF;
    }

    return os;
}

// outputLength = 출력 바이트 길이 (글자 두개)
// seedLength = 시드 입력 바이트 길이
void MGF(unsigned char *mgfSeed, unsigned int seedLength, unsigned char *dest,
         unsigned int outputLength, int sha2_ndx) {
    unsigned long hlen = findSHA[sha2_ndx];
    if (outputLength > (hlen << 32)) return;
    unsigned long max = outputLength / hlen;
    if (outputLength % hlen) max++;
    int now = 0;

    for (unsigned long i = 0; i < max && now < outputLength; i++) {
        unsigned char *C = (unsigned char *)malloc(seedLength + 4);
        unsigned char *os = I2OSP(i, 4);
        int j;
        for (j = 0; j < seedLength; j++) {
            C[j] = mgfSeed[j];
        }

        for (j = 0; j < 4; j++) {
            C[seedLength + j] = os[j];
        }

        unsigned char *val = (unsigned char *)malloc(hlen);
        hash(C, seedLength + 4, val, sha2_ndx);
        for (j = 0; j < hlen && j + now < outputLength; j++) {
            dest[j + now] = val[j];
        }
        now += j;
        free(os);
        free(C);
        free(val);
    }
}

/*
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label,
                       const void *e, const void *n, void *c, int sha2_ndx) {
    int k = RSAKEYSIZE / 8;        // RSA modulus size in bytes
    int hlen = findSHA[sha2_ndx];  // Length of the hash function output
    int MLen = (int)mLen;
    // check to label length (step 1 - a)
    // message length is too long (step 1 - b)
    if (MLen > k - 2 * hlen - 2) {
        return PKCS_MSG_TOO_LONG;
    }
    // Let lHash = Hash(L), an octet string of length hlen (step 2 - a)
    unsigned char *lHash =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));
    hash(label, strlen(label), lHash, sha2_ndx);

    // Generate a padding string PS (step 2 - b)
    int padding_size = k - MLen - 2 * hlen - 2;

    // a data block DB of length k - hlen - 1 octets (step c)
    int DBlength = k - hlen - 1;
    unsigned char *DB =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));

    for (int i = 0; i < hlen; i++) {
        DB[i] = lHash[i];
    }
    unsigned char *message = (unsigned char *)m;
    for (int i = 0; i < MLen; i++) {
        DB[i + hlen + padding_size + 1] = message[i];
    }

    DB[hlen + padding_size] = 1;
    // Generate a random octet string seed of length hlen. (step d)
    unsigned char *seed = (unsigned char *)malloc(hlen);
    for (int i = 0; i < hlen; i++) {
        uint8_t random_byte =
            (uint8_t)arc4random_uniform(256);  // generate random byte
        seed[i] = random_byte;
    }

    // Let dbMask = MGF(seed, k - hlen - 1) (step e)
    int dbMaskLen = k - hlen - 1;
    unsigned char *dbMask =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));

    MGF(seed, hlen, dbMask, DBlength, sha2_ndx);

    unsigned char *maskedDB =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));
    for (int i = 0; i < DBlength; i++) {
        maskedDB[i] = dbMask[i] ^ DB[i];
    }

    // Let seedMask = MGF(maskedDB, hlen)(step g)
    unsigned char *seedMask =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));
    MGF(maskedDB, DBlength, seedMask, hlen, sha2_ndx);
    unsigned char *maskedSeed =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));

    for (int i = 0; i < hlen; i++) {
        maskedSeed[i] = seedMask[i] ^ seed[i];
    }
    unsigned char *tmp = (unsigned char *)c;
    tmp[0] = 0;
    int start = 1;
    for (int i = 0; i < hlen; i++) {
        tmp[start + i] = maskedSeed[i];
    }
    start += hlen;
    for (int i = 0; i < DBlength; i++) {
        tmp[start + i] = maskedDB[i];
    }
    start += DBlength;
    rsa_cipher(c, e, n);

    free(seedMask);
    free(dbMask);
    free(maskedDB);
    free(maskedSeed);
    free(DB);
    free(lHash);
    return 0;
}
/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d,
                       const void *n, const void *c, int sha2_ndx) {
    int k = RSAKEYSIZE / 8;        // RSA modulus size in bytes
    int hlen = findSHA[sha2_ndx];  // Length of the hash function output

    unsigned char *all = (unsigned char *)malloc(k * sizeof(unsigned char));
    for (int i = 0; i < k; i++) {
        const unsigned char *temp;
        temp = (const unsigned char *)c + i;
        all[i] = *temp;
    }
    rsa_cipher(all, d, n);

    if (all[0] != 0) return PKCS_INITIAL_NONZERO;
    unsigned char *maskedSeed =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));

    for (int i = 0; i < hlen; i++) {
        maskedSeed[i] = all[i + 1];
    }

    int DBlength = k - hlen - 1;
    unsigned char *maskedDB =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));

    for (int i = 0; i < DBlength; i++) {
        maskedDB[i] = all[i + 1 + hlen];
    }
    free(all);

    unsigned char *seedMask =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));
    MGF(maskedDB, DBlength, seedMask, hlen, sha2_ndx);
    unsigned char *seed = (unsigned char *)malloc(hlen * sizeof(unsigned char));
    for (int i = 0; i < hlen; i++) {
        seed[i] = seedMask[i] ^ maskedSeed[i];
    }
    free(seedMask);
    free(maskedSeed);
    unsigned char *dbMask =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));
    MGF(seed, hlen, dbMask, DBlength, sha2_ndx);
    unsigned char *DB =
        (unsigned char *)malloc(DBlength * sizeof(unsigned char));
    for (int i = 0; i < DBlength; i++) {
        DB[i] = dbMask[i] ^ maskedDB[i];
    }
    free(seed);
    free(dbMask);
    free(maskedDB);

    unsigned char *lHash =
        (unsigned char *)malloc(hlen * sizeof(unsigned char));
    hash(label, strlen(label), lHash, sha2_ndx);

    for (int i = 0; i < hlen; i++) {
        if (lHash[i] != DB[i]) return PKCS_HASH_MISMATCH;
    }
    int pos = hlen;
    while (DB[pos] == 0) pos++;
    *mLen = DBlength - pos - 1;
    if (DB[pos] != 0x01) return PKCS_INVALID_PS;

    if (*mLen > k - 2 * hlen - 2) {
        return PKCS_MSG_TOO_LONG;
    }
    unsigned char *dest = (unsigned char *)m;
    for (int i = 0; i < *mLen; i++) {
        dest[i] = DB[DBlength - *mLen + i];
    }
    free(lHash);
    free(DB);
    return 0;
}
// k = signers rsa priv/key m message to be signed,an octet string
// output should be message too long,encoding error
static void sha_gen(int sha2_ndx, const unsigned char *message,
                    unsigned int len, unsigned char *digest) {
    void (*f[6])(const unsigned char *, unsigned int, unsigned char *) = {
        sha224, sha256, sha384, sha512, sha512_224, sha512_256};
    if (sha2_ndx >= 0 && sha2_ndx <= 5) f[sha2_ndx](message, len, digest);
}
/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를
 * 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n,
                    void *s, int sha2_ndx) {
    int bytesize = RSAKEYSIZE / 8;
    int hlen = findSHA[sha2_ndx];
    int DB_len = bytesize - hlen - 1;
    int PS_len = DB_len - hlen;

    unsigned char M_hash[hlen];
    unsigned char M_prime[8 + 2 * hlen];
    unsigned char H[hlen];
    unsigned char DB[DB_len];
    unsigned char MGF[DB_len];
    unsigned char MDB[DB_len];
    unsigned char EM[bytesize];
    uint8_t salt[hlen];

    hash(m, mLen, M_hash, sha2_ndx);

    arc4random_buf(&salt, sizeof(uint8_t) * hlen);

    //  M_prime에 만들어진 요소들을 결합한다.
    memset(M_prime, 0x00, sizeof(char) * 8);
    memcpy(M_prime + sizeof(char) * 8, M_hash, sizeof(char) * hlen);
    memcpy(M_prime + sizeof(char) * (8 + hlen), salt, sizeof(char) * hlen);
    hash(M_prime, sizeof(M_prime), H, sha2_ndx);

    // MGF(H, hlen, MGF, DB_len, sha2_ndx);

    memset(DB, 0x00, sizeof(char) * PS_len);
    memset(DB + sizeof(char) * PS_len, 0x01, sizeof(char));
    memcpy(DB + sizeof(char) * (PS_len + 1), salt, sizeof(char) * hlen);

    for (int i = 0; i < DB_len; ++i) MDB[i] = DB[i] ^ MGF[i];
    MDB[0] = 0x0;

    memcpy(EM, MDB, DB_len);
    memcpy(EM + sizeof(char) * DB_len, H, sizeof(char) * hlen);
    memset(EM + sizeof(char) * (DB_len + hlen), 0xBC, sizeof(char));
    //  rsa sign

    int res = rsa_cipher(EM, d, n);
    if (!res) memcpy(s, EM, sizeof(EM));
    return res;
}
/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로
 * 검증한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n,
                      const void *s, int sha2_ndx) {
    int bytesize = RSAKEYSIZE / 8;
    int hlen = findSHA[sha2_ndx];
    int DB_len = bytesize - hlen - 1;
    int PS_len = DB_len - hlen;

    if (mLen != bytesize || bytesize != RSAKEYSIZE / 8) {
        return 0;
    }

    mpz_t signature;
    mpz_init(signature);
    mpz_import(signature, bytesize, 1, 1, 0, 0, s);

    mpz_t m_representative;
    mpz_init(m_representative);
    mpz_powm(m_representative, signature, *((mpz_t *)e), *((mpz_t *)n));

    unsigned char EM[bytesize];
    mpz_export(EM, NULL, 1, 1, 0, 0, m_representative);

    if (EM[bytesize - 1] != 0xBC) {
        return 0;
    }

    unsigned char maskedDB[DB_len];
    unsigned char H[hlen];

    memcpy(maskedDB, EM, DB_len);
    memcpy(H, EM + DB_len, hlen);

    unsigned char mask = 0xFF << (8 - 8 * bytesize + 8 * hlen);
    if ((maskedDB[0] & mask) != 0) {
        return 0;
    }

    unsigned char dbMask[DB_len];
    MGF(H, hlen, dbMask, DB_len, sha2_ndx);

    for (int i = 0; i < DB_len; i++) {
        maskedDB[i] ^= dbMask[i];
    }

    maskedDB[0] &= ~mask;

    for (int i = 0; i < PS_len; i++) {
        if (maskedDB[i] != 0) {
            return 0;
        }
    }
    if (maskedDB[PS_len] != 0x01) {
        return 0;
    }

    unsigned char salt[hlen];
    memcpy(salt, maskedDB + PS_len + 1, hlen);

    unsigned char M_prime[8 + hlen + hlen];
    memset(M_prime, 0x00, 8);
    memcpy(M_prime + 8, H, hlen);
    memcpy(M_prime + 8 + hlen, salt, hlen);

    unsigned char H_prime[hlen];
    hash(M_prime, sizeof(M_prime), H_prime, sha2_ndx);

    if (memcmp(H, H_prime, hlen) != 0) {
        return 0;
    }

    mpz_clear(signature);
    mpz_clear(m_representative);

    return 1;
}
