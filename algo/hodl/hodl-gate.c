#include <memory.h>
#include <stdlib.h>

#include "miner.h"
#include "algo-gate-api.h"
#include "hodl.h"
#include "hodl-wolf.h"


void hodl_set_target( struct work* work, double diff )
{
     diff_to_target(work->target, diff / 8388608.0 );
}

// other algos that use a scratchbuf allocate one per miner thread
// and define it locally.
// Hodl only needs one scratchbuf total but the allocation is done in the
// miner thread, so use a flag.
// All miner threads must point to the same buffer. To do this save a copy
// of the allocated buffer pointer to use instead of malloc.

unsigned char *hodl_scratchbuf = NULL;
bool hodl_scratchbuf_allocated = false;

bool hodl_get_scratchbuf( unsigned char** scratchbuf )
{
  // only alloc one
  if ( !hodl_scratchbuf_allocated )
  {
      hodl_scratchbuf = (unsigned char*)malloc( 1 << 30 );
      hodl_scratchbuf_allocated = ( hodl_scratchbuf != NULL );
  }
  *scratchbuf = hodl_scratchbuf;
  return ( *scratchbuf != NULL );
}

/*
void hodl_reverse_endian_17_19( uint32_t* ntime, uint32_t* nonce,
                                struct work* work )
{
    le32enc(ntime, work->data[17]);
    le32enc(nonce, work->data[19]);
}
*/

char *hodl_build_stratum_request( char* req, struct work* work, 
       unsigned char *xnonce2str, char* ntimestr, char* noncestr  )
{
     uint32_t nstartloc, nfinalcalc;
     char nstartlocstr[9], nfinalcalcstr[9];

     le32enc(&nstartloc, work->data[20]);
     le32enc(&nfinalcalc, work->data[21]);
     bin2hex(nstartlocstr, (const unsigned char *)(&nstartloc), 4);
     bin2hex(nfinalcalcstr, (const unsigned char *)(&nfinalcalc), 4);
     sprintf( req, "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
           rpc_user, work->job_id, xnonce2str, ntimestr, noncestr,
           nstartlocstr, nfinalcalcstr );
}

void hodl_set_data_size( uint32_t* data_size, uint32_t* adata_sz,
                         struct work* work )
{
  *data_size = sizeof(work->data);
  *adata_sz  = ARRAY_SIZE(work->data);
} 

void hodl_build_extraheader( struct work* work, struct stratum_ctx *sctx )
{
        work->data[17] = le32dec(sctx->job.ntime);
        work->data[18] = le32dec(sctx->job.nbits);
        work->data[22] = 0x80000000;
        work->data[31] = 0x00000280;
}

pthread_barrier_t hodl_barrier;

void hodl_thread_barrier_init()
{
  pthread_barrier_init( &hodl_barrier, NULL, opt_n_threads);
}

void hodl_thread_barrier_wait()
{
   pthread_barrier_wait( &hodl_barrier );
}

static struct work hodl_work;
uint32_t nNonce;

void hodl_backup_work_data( struct work* g_work )
{
  if ( memcmp( hodl_work.data, g_work->data, 76 ) )
  {
        work_free( &hodl_work );
        work_copy( &hodl_work, g_work );
   }
//                    pthread_mutex_unlock(&g_work_lock);
   nNonce = ( clock() + rand() ) % 9999;
}

void hodl_restore_work_data( struct work* work )
{
  if ( memcmp( work->data, hodl_work.data, 76 ) )
  {
     work_free( work );
     work_copy( work, &hodl_work );
  }
  work->data[19] = swab32(nNonce);
}

bool hodl_do_all_threads ()
{
  return false;
}

void hodl_get_pseudo_random_data( struct work* work, char* scratchbuf,
                                  int thr_id )
{
#ifdef NO_AES_NI
  GetPsuedoRandomData( scratchbuf, work->data, thr_id );
#else
  GenRandomGarbage( scratchbuf, work->data, thr_id );  
#endif
}

bool register_hodl_algo ( algo_gate_t* gate )
{
#ifdef NO_AES_NI
  gate->aes_ni_optimized = (void*)&return_false;
  gate->scanhash               = (void*)&scanhash_hodl;
  gate->set_data_size          = (void*)&hodl_set_data_size;
#else
  gate->aes_ni_optimized = (void*)&return_true;
  gate->scanhash               = (void*)&scanhash_hodl_wolf;
#endif
  gate->set_target             = (void*)&hodl_set_target;
  gate->get_scratchbuf         = (void*)&hodl_get_scratchbuf;
//  gate->reverse_endian_17_19   = (void*)&hodl_reverse_endian_17_19;
  gate->build_stratum_request  = (void*)&hodl_build_stratum_request;
//  gate->set_data_size          = (void*)&hodl_set_data_size;
  gate->build_extraheader      = (void*)&hodl_build_extraheader;
  gate->thread_barrier_init    = (void*)&hodl_thread_barrier_init;
  gate->thread_barrier_wait    = (void*)&hodl_thread_barrier_wait;
  gate->backup_work_data       = (void*)&hodl_backup_work_data;
  gate->restore_work_data      = (void*)&hodl_restore_work_data;
  gate->init_nonceptr          = (void*)&do_nothing;
  gate->get_pseudo_random_data = (void*)&hodl_get_pseudo_random_data;
  gate->do_all_threads         = (void*)&hodl_do_all_threads;
  return true;
}


