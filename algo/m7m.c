#include "miner.h"
#include "algo-gate-api.h"
#include <gmp.h> /* user MPIR lib for vstudio */
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <float.h>
#include <math.h>

#include "algo/sha2/sph-sha2.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/haval/sph-haval.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/ripemd/sph_ripemd.h"

#include "crypto/magimath.h"


static bool cputest = false;
static uint32_t* hashtest = NULL;

static inline void mpz_set_uint256(mpz_t r, uint8_t *u)
{
	mpz_import(r, 32 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static inline void mpz_set_uint512(mpz_t r, uint8_t *u)
{
	mpz_import(r, 64 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u);
}

static inline void set_one_if_zero(uint8_t *hash512) {
	for (int i = 0; i < 32; i++) {
		if (hash512[i] != 0) {
			return;
		}
	}
	hash512[0] = 1;
}

static bool fulltest_m7hash(const uint32_t *hash32, const uint32_t *target32)
{
	int i;
	bool rc = true;

	const unsigned char *hash = (const unsigned char *)hash32;
	const unsigned char *target = (const unsigned char *)target32;
	for (i = 31; i >= 0; i--) {
		if (hash[i] != target[i]) {
			rc = hash[i] < target[i];
			break;
		}
	}

	return rc;
}

static __thread mpf_t mpsqrt;
static __thread int s_digits = -1;

#define BITS_PER_DIGIT 3.32192809488736234787
#define EPS (DBL_EPSILON)

#define NM7M 5
#define SW_DIVS 5
#define M7_MIDSTATE_LEN 76

typedef struct {
    sph_sha256_context       sha256;
    sph_sha512_context       sha512;
    sph_keccak512_context    keccak;
    sph_whirlpool_context    whirlpool;
    sph_haval256_5_context   haval;
    sph_tiger_context        tiger;
    sph_ripemd160_context    ripemd;
} m7m_ctx_holder;

sph_sha256_context m7m_ctx_final_sha256;
m7m_ctx_holder m7m_ctx1, m7m_ctx2;

void init_m7m_ctx()
{
    sph_sha256_init(&m7m_ctx_final_sha256);
    sph_sha256_init(&m7m_ctx1.sha256);
    sph_sha512_init(&m7m_ctx1.sha512);
    sph_keccak512_init(&m7m_ctx1.keccak);
    sph_whirlpool_init(&m7m_ctx1.whirlpool);
    sph_haval256_5_init(&m7m_ctx1.haval);
    sph_tiger_init(&m7m_ctx1.tiger);
    sph_ripemd160_init(&m7m_ctx1.ripemd);
}

int scanhash_m7m(int thr_id, struct work *work, uint64_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) data[32];
	uint8_t  _ALIGN(128) bhash[7][64];
	uint32_t _ALIGN(128) hash[8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t *data_p64 = data + (M7_MIDSTATE_LEN / sizeof(data[0]));
	uint32_t n = pdata[19];
	const uint32_t first_nonce = pdata[19];
	char data_str[161], hash_str[65], target_str[65];
	uint8_t *bdata = 0;
	mpz_t bns[8];
	int rc = 0;
	int bytes, nnNonce2;

        m7m_ctx_holder ctx, ctx2;
        memcpy( &ctx, &m7m_ctx1, sizeof(m7m_ctx1) );
        sph_sha256_context ctxf_sha256;
    memcpy( &ctxf_sha256, &m7m_ctx_final_sha256, sizeof(sph_sha256_context) );

	mpz_t product;
	mpz_init(product);

	for(int i=0; i < 8; i++){
		mpz_init(bns[i]);
	}

	memcpy(data, pdata, 80);

	sph_sha256 (&ctx.sha256, data, M7_MIDSTATE_LEN);
	sph_sha512 (&ctx.sha512, data, M7_MIDSTATE_LEN);
	sph_keccak512 (&ctx.keccak, data, M7_MIDSTATE_LEN);
	sph_whirlpool (&ctx.whirlpool, data, M7_MIDSTATE_LEN);
	sph_haval256_5 (&ctx.haval, data, M7_MIDSTATE_LEN);
	sph_tiger (&ctx.tiger, data, M7_MIDSTATE_LEN);
	sph_ripemd160 (&ctx.ripemd, data, M7_MIDSTATE_LEN);

	mpf_t mpa1, mpb1, mpt1;
	mpf_t mpa2, mpb2, mpt2;
	mpf_t magifpi;
	mpf_t mpsft;

	mpz_t magipi;
	mpz_t magisw;
	mpz_init(magipi);
	mpz_init(magisw);

	do {

		if (!cputest)
			data[19] = n++;
		else
			hashtest = hash;

		nnNonce2 = (int)(data[19]/2);
		//memset(bhash, 0, 7 * 64);
		memset(&bhash[0][32], 0, 32); // sha256
		memset(&bhash[4][32], 0, 32 + 64*2); // haval/tiger/ripemd

                memcpy( &ctx2, &ctx, sizeof(m7m_ctx1) );

		sph_sha256 (&ctx2.sha256, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_sha256_close(&ctx2.sha256, (void*)(bhash[0]));

		sph_sha512 (&ctx2.sha512, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_sha512_close(&ctx2.sha512, (void*)(bhash[1]));

		sph_keccak512 (&ctx2.keccak, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_keccak512_close(&ctx2.keccak, (void*)(bhash[2]));

		sph_whirlpool (&ctx2.whirlpool, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_whirlpool_close(&ctx2.whirlpool, (void*)(bhash[3]));

		sph_haval256_5 (&ctx2.haval, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_haval256_5_close(&ctx2.haval, (void*)(bhash[4]));

		sph_tiger (&ctx2.tiger, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_tiger_close(&ctx2.tiger, (void*)(bhash[5]));

		sph_ripemd160 (&ctx2.ripemd, data_p64, 80 - M7_MIDSTATE_LEN);
		sph_ripemd160_close(&ctx2.ripemd, (void*)(bhash[6]));

		for(int i=0; i < 7; i++){
			set_one_if_zero(bhash[i]);
			mpz_set_uint512(bns[i], bhash[i]);
		}

		mpz_set_ui(bns[7],0);

		for(int i=0; i < 7; i++){
			mpz_add(bns[7], bns[7], bns[i]);
		}

		mpz_set_ui(product,1);

		for(int i=0; i < 8; i++){
			mpz_mul(product,product,bns[i]);
		}

		mpz_pow_ui(product, product, 2);

		bytes = mpz_sizeinbase(product, 256);
		bdata = (uint8_t *)realloc(bdata, bytes);
		mpz_export((void *)bdata, NULL, -1, 1, 0, 0, product);

		sph_sha256 (&ctxf_sha256, bdata, bytes);
		sph_sha256_close(&ctxf_sha256, (void*)(hash));

		const int digits=(int)((sqrt((double)(nnNonce2))*(1.+EPS))/9000+75);
		if (digits != s_digits) {
			int prec = (int)(digits*BITS_PER_DIGIT+16);
			mpf_set_default_prec(prec);
			if (s_digits == -1) mpf_init(mpsqrt);
			s_digits = digits;
			mpf_set_ui(mpsqrt, 2);
			mpf_sqrt(mpsqrt, mpsqrt);
			mpf_ui_div(mpsqrt, 1, mpsqrt); // 1 / √2
		}

		mpf_init(magifpi);
		mpf_init(mpsft);
		mpf_init(mpa1);
		mpf_init(mpb1);
		mpf_init(mpt1);

		mpf_init(mpa2);
		mpf_init(mpb2);
		mpf_init(mpt2);

		uint32_t usw_ = sw_(nnNonce2, SW_DIVS);
		if (usw_ < 1) usw_ = 1;
		mpz_set_ui(magisw, usw_);
		uint32_t mpzscale = (uint32_t) mpz_size(magisw);

		for(int i=0; i < NM7M; i++)
		{
			const int iterations = 20;

			if (mpzscale > 1000) mpzscale = 1000;
			else if (mpzscale < 1) mpzscale = 1;

			mpf_set_d(mpt1, 0.25*mpzscale);

			mpf_set(mpb1, mpsqrt); // B' = 1 / √2 => pow(2, -0.5)

			mpf_set_ui(mpa1, 1); // A' = 1
			uint32_t p = 1;

			for(int j=0; j <= iterations; j++){
				// A = AVG(A',B')
				mpf_add(mpa2, mpa1, mpb1); // A = A' + B'
				mpf_div_ui(mpa2, mpa2, 2); // A /= 2

				// B = √(A'B')
				mpf_mul(mpb2, mpa1, mpb1); // B = A' * B'
				mpf_abs(mpb2, mpb2);       // B = ABS(B)
				mpf_sqrt(mpb2, mpb2);      // B = √B
				mpf_swap(mpb1, mpb2);

				// T = √(A'-A)
				mpf_sub(mpt2, mpa1, mpa2); // T = A' - A
				mpf_abs(mpt2, mpt2);       // T = ABS(T)
				mpf_sqrt(mpt2, mpt2);      // T = √T
				mpf_swap(mpa1, mpa2);

				// T = T' - T*P
				mpf_mul_ui(mpt2, mpt2, p); // T *= P
				mpf_sub(mpt1, mpt1, mpt2); // T = T' - T

				p <<= 1;
			}

			// PI = (A + B)²/4
			mpf_add(magifpi, mpa1, mpb1);
			mpf_pow_ui(magifpi, magifpi, 2);
			mpf_div_ui(magifpi, magifpi, 4);

			// PI = PI / |T|
			mpf_abs(mpt1, mpt1);
			mpf_div(magifpi, magifpi, mpt1);

			// PI = Extract float part digits
			mpf_set_ui(mpsft, 10);
			mpf_pow_ui(mpsft, mpsft, digits/2);
			mpf_mul(magifpi, magifpi, mpsft);
			mpz_set_f(magipi, magifpi);

			mpz_add(product,product,magipi);
			mpz_add(product,product,magisw);

			mpz_set_uint256(bns[0], (void*)(hash));
			mpz_add(bns[7], bns[7], bns[0]);

			mpz_mul(product,product,bns[7]);
			mpz_cdiv_q (product, product, bns[0]);
			if (mpz_sgn(product) <= 0) mpz_set_ui(product,1);

			bytes = mpz_sizeinbase(product, 256);
			mpzscale = bytes;
			bdata = (uint8_t *)realloc(bdata, bytes);
			mpz_export(bdata, NULL, -1, 1, 0, 0, product);

          memcpy( &ctxf_sha256, &m7m_ctx_final_sha256,
                                  sizeof(sph_sha256_context) );
			sph_sha256 (&ctxf_sha256, bdata, bytes);
			sph_sha256_close(&ctxf_sha256, (void*)(hash));
		}

		mpf_clear(magifpi);
		mpf_clear(mpsft);
		mpf_clear(mpa1);
		mpf_clear(mpb1);
		mpf_clear(mpt1);

		mpf_clear(mpa2);
		mpf_clear(mpb2);
		mpf_clear(mpt2);

		rc = fulltest_m7hash(hash, ptarget);
		if (rc) {
			work_set_target_ratio(work, hash);
			if (opt_debug) {
				bin2hex(hash_str, (unsigned char *)hash, 32);
				bin2hex(target_str, (unsigned char *)ptarget, 32);
				bin2hex(data_str, (unsigned char *)data, 80);
				applog(LOG_DEBUG, "DEBUG: [%d thread] Found share!\ndata   %s\nhash   %s\ntarget %s", thr_id,
					data_str,
					hash_str,
					target_str);
			}

			pdata[19] = data[19];

			goto out;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = n;

out:
	mpz_clear(magipi);
	mpz_clear(magisw);
	for(int i=0; i < 8; i++) {
		mpz_clear(bns[i]);
	}
	mpz_clear(product);
	free(bdata);

	*hashes_done = n - first_nonce + 1;
	return rc;
}

/* --cputest */
void m7mhash(void *output, const void *input)
{
	uint64_t hashes_done = 0;
	struct work work;
	memset(&work, 0, sizeof(struct work));
	memcpy(work.data, input, 80);
	cputest = true;
	scanhash_m7m(0, &work, 0, &hashes_done);
	if (hashtest)
		memcpy(output, hashtest, 32);
	cputest = false;
}

bool m7m_work_decode( const json_t *val, struct work *work )
{
    int i;
    int data_size   = sizeof(work->data);
    int target_size = sizeof(work->target);
    int adata_sz    = ARRAY_SIZE(work->data);
    int atarget_sz  = ARRAY_SIZE(work->target);

    algo_gate.set_data_and_target_size( &data_size, &target_size,
                                 &adata_sz,  &atarget_sz, &allow_mininginfo );

    if ( unlikely(!jobj_binary( val, "data", work->data, data_size )) )
    {
        applog(LOG_ERR, "JSON invalid data");
        return false;
    }
    if ( unlikely(!jobj_binary( val, "target", work->target, target_size )) )
    {
        applog(LOG_ERR, "JSON invalid target");
        return false;
    }
    return true;
}

void m7m_reverse_endian( struct work *work )
{
   for ( int i = 0; i < 32; i++ )
      be32enc( &work->data[i], work->data[i] );
}

bool register_m7m_algo( algo_gate_t *gate )
{
  gate->init_ctx            = (void*)&init_m7m_ctx;
  gate->scanhash            = (void*)&scanhash_m7m;
  gate->hash                = (void*)&m7mhash;
  gate->hash_alt            = (void*)&m7mhash;
  gate->encode_endian_17_19 = (void*)&encode_big_endian_17_19;
  gate->suw_build_hex_string = (void*)&set_data_size_80;
  gate->set_target          = (void*)&scrypt_set_target;
  gate->get_max64           = (void*)&get_max64_0x1ffff;
  gate->set_work_data_endian = (void*)&m7m_reverse_endian;
}
