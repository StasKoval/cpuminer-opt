#include "cpuminer-config.h"
#include "miner.h"
#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#ifdef NO_AES_NI
  #include "algo/groestl/sse2/grso.h"
  #include "algo/groestl/sse2/grso-macro.c"
#else
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"  
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGNXY(x,y) x __attribute__ ((aligned(y)))
#else
#define DATA_ALIGNXY(x,y) __declspec(align(y)) x
#endif


typedef struct {
    sph_shavite512_context  shavite;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
     hashState_echo          echo;
     hashState_groestl       groestl;
#endif
     hashState_luffa         luffa;
     cubehashParam           cube;
     hashState_sd            simd;
} x11_ctx_holder;

x11_ctx_holder x11_ctx;

void init_x11_ctx()
{
     init_luffa( &x11_ctx.luffa, 512 );
     cubehashInit( &x11_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x11_ctx.shavite );
     init_sd( &x11_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &x11_ctx.groestl );
     sph_echo512_init( &x11_ctx.echo );
#else
     init_echo( &x11_ctx.echo, 512 );
     init_groestl( &x11_ctx.groestl );
#endif
}

static void x11_hash( void *state, const void *input )
{
#ifdef NO_AES_NI
     grsoState sts_grs;
#endif
     x11_ctx_holder ctx;
     memcpy( &ctx, &x11_ctx, sizeof(x11_ctx) );

//        DATA_ALIGNXY(unsigned char hashbuf[128],16);
     size_t hashptr;
//        DATA_ALIGNXY(sph_u64 hashctA,8);
//        DATA_ALIGNXY(sph_u64 hashctB,8);

//        DATA_ALIGNXY(unsigned char hash[128],16);
     unsigned char hashbuf[128];
     sph_u64 hashctA;
     sph_u64 hashctB;

     unsigned char hash[128];
//     unsigned char hash[128] __attribute__ ((aligned (16)));

     DECL_BLK;
     BLK_I;
     BLK_W;
     BLK_C;

     //---bmw2---

     DECL_BMW;
     BMW_I;
     BMW_U;
     #define M(x)    sph_dec64le_aligned(data + 8 * (x))
     #define H(x)    (h[x])
     #define dH(x)   (dh[x])
     BMW_C;
     #undef M
     #undef H
     #undef dH

     //---grs3----

#ifdef NO_AES_NI
           GRS_I;
           GRS_U;
           GRS_C;

//     sph_groestl512 (&ctx.groestl, hash, 64);
//     sph_groestl512_close(&ctx.groestl, hash);
#else
     update_groestl( &ctx.groestl, (char*)hash,512);
     final_groestl( &ctx.groestl, (char*)hash);
#endif

     //---skein4---

     DECL_SKN;
     SKN_I;
     SKN_U;
     SKN_C;

     //---jh5------

     DECL_JH;
     JH_H;

     //---keccak6---

     DECL_KEC;
     KEC_I;
     KEC_U;
     KEC_C;

//   asm volatile ("emms");

     //--- luffa7

     update_luffa( &ctx.luffa, (const BitSequence*)hash,512);
     final_luffa( &ctx.luffa, (BitSequence*)hash+64);

     //---cubehash---

     cubehashUpdate( &ctx.cube, (const byte*) hash+64,64);
     cubehashDigest( &ctx.cube, (byte*)hash);

     //---shavite---
  
     sph_shavite512( &ctx.shavite, hash, 64);
     sph_shavite512_close( &ctx.shavite, hash+64);

     //-------simd512 vect128 --------------

     update_sd( &ctx.simd, (const BitSequence *)hash+64,512);
     final_sd( &ctx.simd, (BitSequence *)hash);

     //---echo---

#ifdef NO_AES_NI
     sph_echo512 (&ctx.echo, hash, 64);
     sph_echo512_close(&ctx.echo, hash+64);
#else
     update_echo ( &ctx.echo, (const BitSequence *) hash, 512);
     final_echo( &ctx.echo, (BitSequence *) hash+64 );
#endif

//        asm volatile ("emms");
	memcpy(state, hash+64, 32);
}


static void x11hash_alt( void *output, const void *input )
{
        sph_blake512_context     ctx_blake;
        sph_bmw512_context       ctx_bmw;
        sph_groestl512_context   ctx_groestl;
        sph_skein512_context     ctx_skein;
        sph_jh512_context        ctx_jh;
        sph_keccak512_context    ctx_keccak;

        sph_luffa512_context            ctx_luffa1;
        sph_cubehash512_context         ctx_cubehash1;
        sph_shavite512_context          ctx_shavite1;
        sph_simd512_context             ctx_simd1;
        sph_echo512_context             ctx_echo1;

        uint32_t _ALIGN(64) hashA[16], hashB[16];

        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, input, 80);
        sph_blake512_close (&ctx_blake, hashA);

        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, hashA, 64);
        sph_bmw512_close(&ctx_bmw, hashB);

        sph_groestl512_init(&ctx_groestl);
        sph_groestl512 (&ctx_groestl, hashB, 64);
        sph_groestl512_close(&ctx_groestl, hashA);

        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, hashA, 64);
        sph_skein512_close (&ctx_skein, hashB);

        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, hashB, 64);
        sph_jh512_close(&ctx_jh, hashA);

        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hashA, 64);
        sph_keccak512_close(&ctx_keccak, hashB);

        sph_luffa512_init (&ctx_luffa1);
        sph_luffa512 (&ctx_luffa1, hashB, 64);
        sph_luffa512_close (&ctx_luffa1, hashA);

        sph_cubehash512_init (&ctx_cubehash1);
        sph_cubehash512 (&ctx_cubehash1, hashA, 64);
        sph_cubehash512_close(&ctx_cubehash1, hashB);

        sph_shavite512_init (&ctx_shavite1);
        sph_shavite512 (&ctx_shavite1, hashB, 64);
        sph_shavite512_close(&ctx_shavite1, hashA);

        sph_simd512_init (&ctx_simd1);
        sph_simd512 (&ctx_simd1, hashA, 64);
        sph_simd512_close(&ctx_simd1, hashB);

        sph_echo512_init (&ctx_echo1);
        sph_echo512 (&ctx_echo1, hashB, 64);
        sph_echo512_close(&ctx_echo1, hashA);

        memcpy(output, hashA, 32);
}



int scanhash_x11(int thr_id, struct work *work,
             uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];
//       init_x11_ctx();

        be32enc( &endiandata[0], ((uint32_t*)pdata)[0] );
        be32enc( &endiandata[1], ((uint32_t*)pdata)[1] );
        be32enc( &endiandata[2], ((uint32_t*)pdata)[2] );
        be32enc( &endiandata[3], ((uint32_t*)pdata)[3] );
        be32enc( &endiandata[4], ((uint32_t*)pdata)[4] );
        be32enc( &endiandata[5], ((uint32_t*)pdata)[5] );
        be32enc( &endiandata[6], ((uint32_t*)pdata)[6] );
        be32enc( &endiandata[7], ((uint32_t*)pdata)[7] );
        be32enc( &endiandata[8], ((uint32_t*)pdata)[8] );
        be32enc( &endiandata[9], ((uint32_t*)pdata)[9] );
        be32enc( &endiandata[10], ((uint32_t*)pdata)[10] );
        be32enc( &endiandata[11], ((uint32_t*)pdata)[11] );
        be32enc( &endiandata[12], ((uint32_t*)pdata)[12] );
        be32enc( &endiandata[13], ((uint32_t*)pdata)[13] );
        be32enc( &endiandata[14], ((uint32_t*)pdata)[14] );
        be32enc( &endiandata[15], ((uint32_t*)pdata)[15] );
        be32enc( &endiandata[16], ((uint32_t*)pdata)[16] );
        be32enc( &endiandata[17], ((uint32_t*)pdata)[17] );
        be32enc( &endiandata[18], ((uint32_t*)pdata)[18] );
        be32enc( &endiandata[19], ((uint32_t*)pdata)[19] );
        be32enc( &endiandata[20], ((uint32_t*)pdata)[20] );
        be32enc( &endiandata[21], ((uint32_t*)pdata)[21] );
        be32enc( &endiandata[22], ((uint32_t*)pdata)[22] );
        be32enc( &endiandata[23], ((uint32_t*)pdata)[23] );
        be32enc( &endiandata[24], ((uint32_t*)pdata)[24] );
        be32enc( &endiandata[25], ((uint32_t*)pdata)[25] );
        be32enc( &endiandata[26], ((uint32_t*)pdata)[26] );
        be32enc( &endiandata[27], ((uint32_t*)pdata)[27] );
        be32enc( &endiandata[28], ((uint32_t*)pdata)[28] );
        be32enc( &endiandata[29], ((uint32_t*)pdata)[29] );
        be32enc( &endiandata[30], ((uint32_t*)pdata)[30] );
        be32enc( &endiandata[31], ((uint32_t*)pdata)[31] );

//        int kk=0;
//	for (; kk < 32; kk++){
//		be32enc( &endiandata[kk], ((uint32_t*)pdata)[kk] );
//	};

        if ( ptarget[7] == 0 )
        {
          do
          {
            pdata[19] = ++n;
            be32enc( &endiandata[19], n );
            x11_hash( hash64, &endiandata );
            if ( (hash64[7] & 0xFFFFFFFF) == 0 )
            {
               if ( fulltest(hash64, ptarget))
               {
                   *hashes_done = n - first_nonce + 1;
                   return true;
               }
//               else
//               {
//                 applog(LOG_INFO, "Result does not validate on CPU!");
//               }          
             }
          } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }
        else if ( ptarget[7] <=0xF )
        {
           do
           {
             pdata[19] = ++n;
             be32enc( &endiandata[19], n );
             x11_hash( hash64, &endiandata );
             if ( (hash64[7] & 0xFFFFFFF0) == 0 )
             {
               if ( fulltest(hash64, ptarget) )
               {
                 *hashes_done = n - first_nonce + 1;
                 return true;
               }
//               else
//               {
//                 applog(LOG_INFO, "Result %d/%d does not validate on CPU!");
//               }          
             }              
           } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }
        else if ( ptarget[7] <= 0xFF )
        {
          do
          {
            pdata[19] = ++n;
            be32enc( &endiandata[19], n );
            x11_hash( hash64, &endiandata );
            if ( (hash64[7] & 0xFFFFFF00) == 0 )
            {
              if ( fulltest(hash64, ptarget) )
              {
                *hashes_done = n - first_nonce + 1;
                return true;
              }
//              else
//              {
//                applog(LOG_INFO, "Result does not validate on CPU!");
//              }
            }
          } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }
        else if ( ptarget[7] <= 0xFFF )
        {
          do
          {
            pdata[19] = ++n;
            be32enc( &endiandata[19], n );
            x11_hash( hash64, &endiandata );
            if ( (hash64[7] & 0xFFFFF000) == 0 )
            {
              if ( fulltest(hash64, ptarget) )
              {
                *hashes_done = n - first_nonce + 1;
                return true;
              }
//              else
//              {
//                applog(LOG_INFO, "Result does not validate on CPU!");
//              }          
            }
          } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }
        else if ( ptarget[7] <= 0xFFFF )
        {
          do
          {
            pdata[19] = ++n;
            be32enc( &endiandata[19], n );
            x11_hash( hash64, &endiandata );
            if ( (hash64[7] & 0xFFFF0000) == 0)
            {
              if ( fulltest(hash64, ptarget) )
              {
                *hashes_done = n - first_nonce + 1;
                return true;
              }
//            else
//              {
//                applog(LOG_INFO, "Result does not validate on CPU!");
//              }          
            }
          } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }
        else
        {
          do
          {
            pdata[19] = ++n;
            be32enc( &endiandata[19], n );
            x11_hash( hash64, &endiandata );
            if ( fulltest( hash64, ptarget) )
            {
              *hashes_done = n - first_nonce + 1;
              return true;
            }
//            else
//            {
//              applog(LOG_INFO, "Result does not validate on CPU!");
//            }
          } while ( n < max_nonce && !work_restart[thr_id].restart );        
        }

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

int64_t get_x11_max64 ()
{ return 0x3ffffLL; }

bool register_x11_algo( algo_gate_t* gate )
{
  gate->aes_ni_optimized = (void*)&return_true;
  gate->init_ctx  = (void*)&init_x11_ctx;
  gate->scanhash  = (void*)&scanhash_x11;
  gate->hash      = (void*)&x11_hash;
  gate->get_max64 = (void*)&get_x11_max64;
  gate->hash_alt  = (void*)&x11hash_alt;
  return true;
};

