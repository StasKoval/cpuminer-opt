// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
//#include "miner.h"
#include "algo-gate-api.h"

#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "cryptonight.h"

#if defined __unix__ && (!defined __APPLE__)
#include <sys/mman.h>
#elif defined _WIN32
#include <windows.h>
#endif

void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

void do_jh_hash(const void* input, size_t len, char* output) {
    jh_hash(32 * 8, input, 8 * len, (uint8_t*)output);
}

void do_skein_hash(const void* input, size_t len, char* output) {
    skein_hash(8 * 32, input, 8 * len, (uint8_t*)output);
}

void xor_blocks_dst(const uint8_t *restrict a, const uint8_t *restrict b, uint8_t *restrict dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

void (* const extra_hashes[4])( const void *, size_t, char *) =
    { do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash };

//typedef struct {
//     cryptonight_ctx     cn;
//     hashState_groestl  groestl;
//} cn_context_holder;

//cn_context_holder cn_ctx;

//void init_cn_contexts()
//{
//      init_groestl( &ctx.groestl );
//          init_cryptonight( &ctx.cn );
//}


//void cryptonight_hash_ctx( void* output, const void* input, size_t len )
//{
// struct cryptonight_ctx *ctx =
//          (struct cryptonight_ctx*)malloc(sizeof(struct cryptonight_ctx));
//   cryptonight_hash_ctx(output, input, ctx);
//   free(ctx);
//}

void cryptonight_hash( void *restrict output, const void *input, int len )
{

#ifdef NO_AES_NI
  struct cryptonight_ctx ctx;
  cryptonight_hash_ctx ( output, input, &ctx );
#else 
  cryptonight_hash_aes( output, input, len );
#endif
}

void cryptonight_hash_suw( void *restrict output, const void *input )
{
#ifdef NO_AES_NI
  struct cryptonight_ctx ctx;
  cryptonight_hash_ctx ( output, input, &ctx );
#else
  cryptonight_hash_aes( output, input, 76 );
#endif
}

int scanhash_cryptonight( int thr_id, struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done )
 {
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    const uint32_t Htarg = ptarget[7];
    uint32_t hash[32 / 4] __attribute__((aligned(32)));

    do
    {
       *nonceptr = ++n;
       cryptonight_hash(hash, pdata, 76 );
       if (unlikely(hash[7] < ptarget[7]))
       {
           *hashes_done = n - first_nonce + 1;
	   return true;
       }
    } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
    
    *hashes_done = n - first_nonce + 1;
    return 0;
}

int64_t cryptonight_get_max64 ()
{
  return 0x40LL;
}

bool cryptonight_use_rpc2()
{
 return true; 
}

bool register_cryptonight_algo( algo_gate_t* gate )
{
//  gate->init_ctx = &(void*)init_cryptonight_ctx;
  gate->scanhash  = (void*)&scanhash_cryptonight;
  gate->hash      = (void*)&cryptonight_hash_aes;
  gate->hash_suw  = (void*)&cryptonight_hash_aes;  // submit_upstream_work
  gate->get_max64 = (void*)&cryptonight_get_max64;
  gate->use_rpc2  = (void*)&cryptonight_use_rpc2;

// Does Wolf's AES cryptonight use rpc2? and does it need to disable extranonce?
  jsonrpc_2       = true;
//  opt_extranonce  = false;
  return true;
};

