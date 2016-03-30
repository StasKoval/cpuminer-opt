#include <memory.h>

#include "miner.h"
#include "algo/blake/sph_blake.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/skein/sph_skein.h"
#include "algo/keccak/sph_keccak.h"
#include "lyra2.h"
#include "algo-gate-api.h"

typedef struct {
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
        sph_groestl256_context   groestl;
} lyra2re_ctx_holder;

lyra2re_ctx_holder lyra2re_ctx;

void init_lyra2re_ctx()
{
        sph_blake256_init(&lyra2re_ctx.blake);
        sph_keccak256_init(&lyra2re_ctx.keccak);
        sph_skein256_init(&lyra2re_ctx.skein);
        sph_groestl256_init(&lyra2re_ctx.groestl);
}

void lyra2re_hash(void *state, const void *input)
{
        lyra2re_ctx_holder ctx;
        memcpy(&ctx, &lyra2re_ctx, sizeof(lyra2re_ctx));

	uint32_t hashA[8], hashB[8];

	sph_blake256(&ctx.blake, input, 80);
	sph_blake256_close(&ctx.blake, hashA);

	sph_keccak256(&ctx.keccak, hashA, 32);
	sph_keccak256_close(&ctx.keccak, hashB);

	LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

	sph_skein256(&ctx.skein, hashA, 32);
	sph_skein256_close(&ctx.skein, hashB);

	sph_groestl256(&ctx.groestl, hashB, 32);
	sph_groestl256_close(&ctx.groestl, hashA);

	memcpy(state, hashA, 32);
}

int scanhash_lyra2re(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

//        init_lyr2re_x64_ctx();

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		lyra2re_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

int64_t lyra2re_get_max64 ()
{
  return 0xffffLL;
}

void lyra2re_set_target ( struct work* work, double job_diff, double factor)
{
   work_set_target(work, job_diff / (128.0 * factor) );
}

bool register_lyra2re_algo( algo_gate_t* gate )
{
  gate->init_ctx   = (void*)&init_lyra2re_ctx;
  gate->scanhash   = (void*)&scanhash_lyra2re;
  gate->hash       = (void*)&lyra2re_hash;
  gate->hash_alt   = (void*)&lyra2re_hash;
  gate->get_max64  = (void*)&lyra2re_get_max64;
  gate->set_target = (void*)&lyra2re_set_target;
  return true;
};

