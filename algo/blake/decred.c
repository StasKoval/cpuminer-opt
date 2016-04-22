#include "miner.h"
#include "algo-gate-api.h"
#include "sph_blake.h"

#include <string.h>
#include <stdint.h>
#include <memory.h>

static __thread sph_blake256_context blake_mid;
static __thread bool ctx_midstate_done = false;

void decred_hash(void *state, const void *input)
{
        #define MIDSTATE_LEN 128
        sph_blake256_context ctx;

        uint8_t *ending = (uint8_t*) input;
        ending += MIDSTATE_LEN;

        if (!ctx_midstate_done) {
                sph_blake256_init(&blake_mid);
                sph_blake256(&blake_mid, input, MIDSTATE_LEN);
                ctx_midstate_done = true;
        }
        memcpy(&ctx, &blake_mid, sizeof(blake_mid));

        sph_blake256(&ctx, ending, (180 - MIDSTATE_LEN));
        sph_blake256_close(&ctx, state);
}

void decred_hash_simple(void *state, const void *input)
{
        sph_blake256_context ctx;
        sph_blake256_init(&ctx);
        sph_blake256(&ctx, input, 180);
        sph_blake256_close(&ctx, state);
}

int scanhash_decred(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t _ALIGN(128) endiandata[48];
        uint32_t _ALIGN(128) hash32[8];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        #define DCR_NONCE_OFT32 35

        const uint32_t first_nonce = pdata[DCR_NONCE_OFT32];
        const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];

        uint32_t n = first_nonce;

        ctx_midstate_done = false;

#if 1
        memcpy(endiandata, pdata, 180);
#else
        for (int k=0; k < (180/4); k++)
                be32enc(&endiandata[k], pdata[k]);
#endif

#ifdef DEBUG_ALGO
        if (!thr_id) applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

        do {
                //be32enc(&endiandata[DCR_NONCE_OFT32], n);
                endiandata[DCR_NONCE_OFT32] = n;
                decred_hash(hash32, endiandata);

                if (hash32[7] <= HTarget && fulltest(hash32, ptarget)) {
                        work_set_target_ratio(work, hash32);
                        *hashes_done = n - first_nonce + 1;
#ifdef DEBUG_ALGO
                        applog(LOG_BLUE, "Nonce : %08x %08x", n, swab32(n));
                        applog_hash(ptarget);
                        applog_compare_hash(hash32, ptarget);
#endif
                        pdata[DCR_NONCE_OFT32] = n;
                        return 1;
                }

                n++;

        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[DCR_NONCE_OFT32] = n;
        return 0;
}



void decred_calc_network_diff ( struct work* work )
{
   // sample for diff 43.281 : 1c05ea29
   // todo: endian reversed on longpoll could be zr5 specific...
   uint32_t nbits = work->data[29];
   uint32_t bits = (nbits & 0xffffff);
   int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28
   net_diff = (double)0x0000ffff / (double)bits;

   for (int m=shift; m < 29; m++)
       net_diff *= 256.0;
   for (int m=29; m < shift; m++)
       net_diff /= 256.0;
   if ( shift == 28 )
       net_diff *= 256.0; // testnet
   if (opt_debug_diff)
       applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", net_diff, shift, bits);
}

// extra allow_mining_info arg for decred
void decred_set_data_and_target_size( int *data_size, int *target_size,
                                      int *adata_sz,  int *atarget_sz,
                                      bool* allow_mininginfo )
{
   *data_size        = 192;
   *adata_sz         = 180/4;
   *allow_mininginfo = false;
}

// hooked into the display_pok gate function
void decred_decode_extradata( struct work* work, uint64_t* net_blocks )
{
   // some random extradata to make the work unique
   work->data[36] = (rand()*4);
   work->height = work->data[32];
   // required for the getwork pools (multicoin.co)
   if (!have_longpoll && work->height > *net_blocks + 1)
   {
      char netinfo[64] = { 0 };
      if (opt_showdiff && net_diff > 0.)
      {
         if (net_diff != work->targetdiff)
	    sprintf(netinfo, ", diff %.3f, target %.1f", net_diff,
                   work->targetdiff);
	 else
	     sprintf(netinfo, ", diff %.3f", net_diff);
       }
       applog(LOG_BLUE, "%s block %d%s", algo_names[opt_algo], work->height,
                       netinfo);
       *net_blocks = work->height - 1;
   }
}

// hooked into the reverse_endian_17_19 gate function
void decred_reverse_endian_34_35( uint32_t* ntime,  uint32_t* nonce,
                                  struct work* work )
{
   be32enc( ntime, work->data[34] );
   be32enc( nonce, work->data[35] );
}

unsigned char* decred_get_xnonce2str( struct work* work, size_t xnonce1_size )
{
   return abin2hex((unsigned char*)(&work->data[36]), xnonce1_size );
}

/*
void decred_set_data_size( int* data_size, int* adata_sz )
{
  *data_size = 192;
  *adata_sz  = 180 / 4;
}
*/

int  decred_suw_build_hex_string( struct work *work )
{
  for ( int i = 0; i < 180 / sizeof(uint32_t); i++ )
     le32enc( &work->data[i], work->data[i] );
  return 192;
}

void decred_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx,
                 int* headersize, uint32_t* extraheader, int extraheader_size )
{
   // getwork over stratum, getwork merkle + header passed in coinb1
   memcpy(merkle_root, sctx->job.coinbase, 32);
   *headersize = min((int)sctx->job.coinbase_size - 32, extraheader_size );
   memcpy( extraheader, &sctx->job.coinbase[32], *headersize);
}

void decred_build_extraheader( struct work* work, struct stratum_ctx* sctx,
                                uint32_t* extraheader, int headersize )
{
   uint32_t* extradata = (uint32_t*) sctx->xnonce1;

   int i;
   for (i = 0; i < 8; i++) // prevhash
      work->data[1 + i] = swab32(work->data[1 + i]);
   for (i = 0; i < 8; i++) // merkle
      work->data[9 + i] = swab32(work->data[9 + i]);
   for (i = 0; i < headersize/4; i++) // header
      work->data[17 + i] = extraheader[i];
   // extradata
   for (i = 0; i < sctx->xnonce1_size/4; i++)
      work->data[36 + i] = extradata[i];
   for (i = 36 + sctx->xnonce1_size/4; i < 45; i++)
      work->data[i] = 0;
   work->data[37] = (rand()*4) << 8;
   sctx->bloc_height = work->data[32];
   //applog_hex(work->data, 180);
   //applog_hex(&work->data[36], 36);
}

// hooked into ingore_pok function
bool decred_regen_work( int *wkcmp_sz, int* wkcmp_offset,
                            int* nonce_oft )
{
   *wkcmp_sz  = 140;
   *nonce_oft = 140; // 35 * 4
   return true; // ntime not changed ?
}

bool decred_prevent_dupes( uint32_t* nonceptr, struct work* work, struct stratum_ctx* stratum, int thr_id )
{
   if ( have_stratum && strcmp(stratum->job.job_id, work->job_id)  )
      // continue; // need to regen g_work..
      return true;
 
   // extradata: prevent duplicates
   nonceptr[1] += 1;
   nonceptr[2] |= thr_id;
   return false;
}

/*
int64_t decred_get_max64 ()
{
   return 0x3fffffLL;
}
*/

bool register_decred_algo( algo_gate_t* gate )
{
//  gate->init_ctx = &init_blakecoin_ctx;
  gate->scanhash                 = (void*)&scanhash_decred;
  gate->hash                     = (void*)&decred_hash;
  gate->hash_alt                 = (void*)&decred_hash;
//  gate->get_max64                = (void*)&decred_get_max64;
  gate->get_max64                = (void*)&get_max64_0x3fffffLL;
  gate->set_data_and_target_size = (void*)&decred_set_data_and_target_size;
  gate->display_pok              = (void*)&decred_decode_extradata;
  gate->get_xnonce2str           = (void*)&decred_get_xnonce2str;
  gate->encode_endian_17_19      = (void*)&decred_reverse_endian_34_35; 
//  gate->set_data_size            = (void*)&decred_set_data_size;
  gate->suw_build_hex_string     = (void*)&decred_suw_build_hex_string;
  gate->gen_merkle_root          = (void*)&decred_gen_merkle_root;
  gate->build_extraheader        = (void*)&decred_build_extraheader;
  gate->ignore_pok               = (void*)&decred_regen_work;
  gate->prevent_dupes            = (void*)&decred_prevent_dupes;
  have_gbt        = false;
  return true;
}

