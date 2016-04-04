#include "miner.h"
#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "crypto/blake2s.h"

void blake2s_hash(void *output, const void *input)
{
	unsigned char hash[128] = { 0 };
	blake2s_state blake2_ctx;

	blake2s_init(&blake2_ctx, BLAKE2S_OUTBYTES);
	blake2s_update(&blake2_ctx, input, 80);
	blake2s_final(&blake2_ctx, hash, BLAKE2S_OUTBYTES);

	memcpy(output, hash, 32);
}

int scanhash_blake2s(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		blake2s_hash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

int64_t blake2s_get_max64 ()
{
   return 0x7ffffLL;
}

bool register_blake2s_algo( algo_gate_t* gate )
{
//  gate->init_ctx = &init_blake2s_ctx;
  gate->scanhash  = (void*)&scanhash_blake2s;
  gate->hash      = (void*)&blake2s_hash;
  gate->get_max64 = (void*)&blake2s_get_max64;
  return true;
};

