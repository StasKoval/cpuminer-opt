/////////////////////////////
////
////    NEW FEATURE: algo_gate
////
////    algos define targets for their common functions
////    and define a function for miner-thread to call to register
////    their targets. miner thread builds the gate, and array of structs
////    of function pointers, by calling each algo's register function.
//   Functions in this file are used simultaneously by myultiple
//   threads and must therefore be re-entrant.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "miner.h"
#include "algo-gate-api.h"

// define null functions

void     null_init_ctx()
{};

int      null_scanhash(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                   uint32_t  max_nonce, uint64_t *hashes_done)
{
   applog(LOG_WARNING,"SWERR: undefined scanhash function in algo_gate");
   return false;
}

void     null_hash( void *output, const void *pdata, uint32_t len )
{
   applog(LOG_WARNING,"SWERR: null_hash unsafe null function");
};

void     null_hash_suw( void *output, const void *pdata )
{
  applog(LOG_WARNING,"SWERR: null_hash unsafe null function");
};

double null_get_max64()
{
  return 0x1fffffLL;
}

void null_hash_alt   ( void *output, const void *pdata, uint32_t len )
{
  applog(LOG_WARNING,"SWERR: null_hash_alt unsafe null function");
};

bool null_get_scratchbuf( char** scratchbuf )
{
  return true;
};

// This is the value for most, make it the default
void null_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
}

// This is the value for most, make it default
void null_set_target( struct work* work, double job_diff, double factor)
{
   work_set_target( work, job_diff / factor );
}

void null_ignore_pok( int* wkcmp_sz, int* wkcmp_offset )
{}

void null_display_pok ( uint32_t wd0 )
{}

bool null_use_rpc2 ()
{
  return false; 
}

//arg is needed to null func can return original value unchanged
int null_set_data_size( uint32_t data_size )
{ 
  return data_size;
}

void null_set_data_and_target_size( int *data_size, int *target_size,
                                    int *adata_sz,  int *atarget_sz )
{}

void null_wait_for_diff( struct stratum_ctx* stratum ) 
{}

void null_reverse_endian ( struct work* work )
{}

void null_reverse_endian_17_19 (  uint32_t* ntime,  uint32_t* nonce,
                                  uint32_t wd17, uint32_t wd19 )
{}

// initialise all functions to null

init_null_algo_gate( algo_gate_t* gate )
{
   gate->scanhash             = (void*)&null_scanhash;
   gate->hash                 = (void*)&null_hash;
   gate->hash_alt             = (void*)&null_hash_alt;
   gate->hash_suw             = (void*)&null_hash_suw;
   gate->init_ctx             = (void*)&null_init_ctx;
   gate->get_max64            = (void*)&null_get_max64;
   gate->get_scratchbuf       = (void*)&null_get_scratchbuf;
   gate->gen_merkle_root      = (void*)&null_gen_merkle_root;
   gate->set_target           = (void*)&null_set_target;
   gate->ignore_pok           = (void*)&null_ignore_pok;
   gate->display_pok          = (void*)&null_display_pok;
   gate->use_rpc2             = (void*)&null_use_rpc2;
   gate->set_data_size        = (void*)&null_set_data_size;
   gate->set_data_and_target_size = (void*)&null_set_data_and_target_size;
   gate->wait_for_diff        = (void*)&null_wait_for_diff;
   gate->reverse_endian       = (void*)&null_reverse_endian;
   gate->reverse_endian_17_19 = (void*)&null_reverse_endian_17_19;
}

// called by each thread that uses the gate

bool register_algo_gate( int algo, algo_gate_t *gate )
{
   bool rc = true;

   if ( NULL == gate )
   {
     applog(LOG_ERR,"FAIL: algo_gate registration failed, NULL gate\n");
     return false;
   }

   init_null_algo_gate( gate );

   // register the algo to be mined.
   // unimplemented functions will remain at their null value which
   // returns a default successful return code.

   switch (algo)
   {
     case ALGO_SCRYPT:
        register_scrypt_algo( gate );
        break;
     case ALGO_SHA256D:
        register_sha256d_algo( gate );
        break;
     case ALGO_KECCAK:
        register_keccak_algo( gate );
        break;
     case ALGO_HEAVY:
        register_heavy_algo( gate );
        break;
     case ALGO_AXIOM:
        register_axiom_algo( gate );
        break;
     case ALGO_BLAKE:
        register_blake_algo( gate );
        break;
     case ALGO_BLAKECOIN:
        register_blakecoin_algo( gate );
        break;
     case ALGO_BLAKE2S:
        register_blake2s_algo( gate );
        break;
     case ALGO_C11:
        register_c11_algo( gate );
        break;
     case ALGO_CRYPTOLIGHT:
        register_cryptolight_algo( gate );
        break;
     case ALGO_CRYPTONIGHT:
        register_cryptonight_algo( gate );
        break;
     case ALGO_DROP:
        register_drop_algo( gate );
        break;
     case ALGO_FRESH:
        register_fresh_algo( gate );
        break;
     case ALGO_DMD_GR:
     case ALGO_GROESTL:
        register_groestl_algo( gate );
        break;
     case ALGO_LUFFA:
        register_luffa_algo( gate );
        break;
     case ALGO_LYRA2RE:
        register_lyra2re_algo( gate );
        break;
     case ALGO_LYRA2REV2:
        register_lyra2rev2_algo( gate );
        break;
     case ALGO_MYR_GR:
        register_myriad_algo( gate );
        break;
     case ALGO_NEOSCRYPT:
        register_neoscrypt_algo( gate );
        break;
     case ALGO_NIST5:
       	register_nist5_algo( gate );
        break;
     case ALGO_PENTABLAKE:
        register_pentablake_algo( gate );
        break;
     case ALGO_PLUCK:
        register_pluck_algo( gate );
        break;
     case ALGO_QUARK:
        register_quark_algo( gate );
        break;
     case ALGO_QUBIT:
        register_qubit_algo( gate );
        break;
     case ALGO_SHAVITE3:
        register_shavite_algo( gate );
        break;
     case ALGO_SIB:
        register_sib_algo( gate );
        break;
     case ALGO_SKEIN:
        register_skein_algo( gate );
        break;
     case ALGO_SKEIN2:
        register_skein2_algo( gate );
        break;
     case ALGO_S3:
        register_s3_algo( gate );
        break;
     case ALGO_VANILLA:
        register_vanilla_algo( gate );
        break;
     case ALGO_X11:
        register_x11_algo( gate );
        break;
     case ALGO_X13:
        register_x13_algo( gate );
        break;
     case ALGO_X14:
        register_x14_algo( gate );
        break;
     case ALGO_X15:
        register_x15_algo( gate );
        break;
     case ALGO_X17:
        register_x17_algo( gate );
        break;
     case ALGO_YESCRYPT:
        register_yescrypt_algo( gate );
        break;
     case ALGO_ZR5:
        register_zr5_algo( gate );
        break;
     default:
        applog(LOG_ERR,"FAIL: algo_gate registration failed, unknown algo %s.\n", algo_names[opt_algo] );
         return false;
   }

  // ensure required functions were defined.
  if (  gate->scanhash == null_scanhash )
  {
    applog(LOG_ERR, "Fail: Required algo_gate functions undefined\n");
    return false;
  }
  return true;
}

// run the hash_alt gate function for a specific algo
void exec_hash_function( int algo, void *output, const void *pdata )
{
 int len = 0; // dummy arg
  algo_gate_t gate;   
  gate.hash = (void*)&null_hash;
  register_algo_gate( algo, &gate );
  gate.hash( output, pdata, len );  
}


// an algo can have multiple aliases but the aliases must be unique

#define PROPER (1)
#define ALIAS  (0)

// Need to sort out all the blakes
// blake256r14 is apparently decred
// Vanilla was obvious, blakecoin is almosty identical to vanilla
// What is blake2s, pentablake?

// The only difference between the alias and the proper algo name is the
// proper name must be unique and defined in ALGO_NAMES, there may be
// multiple aliases but are not defined in ALGO_NAMES.
// New aliases can be added anywhere in the array as long as NULL is last.
// Alphabetic order of alias is recommended.
const char* algo_alias_map[][2] =
{
//   alias                proper
  { "blake256r8",        "blakecoin"   },
  { "blake256r8vnl",     "vanilla"     },
  { "cryptonight-light", "cryptolight" },
  { "droplp",            "drop"        },
  { "flax",              "c11"         },
  { "lyra2",             "lyra2re"     },
  { "lyra2v2",           "lyra2rev2"   },
  { "myriad",            "myr-gr"      },
  { "neo",               "neoscrypt"   },
  { "sibcoin",           "sib"         },
  { "ziftr",             "zr5"         },
  { NULL,                NULL          }   
};

// if arg is a valid alias for a known algo it is updated with the proper name.
// No validation of the algo or alias is done, It is the responsinility of the
// calling function to validate the algo after return.
void get_algo_alias( char** algo_or_alias )
{
  int i;
  for ( i=0; algo_alias_map[i][ALIAS]; i++ )
    if ( !strcasecmp( *algo_or_alias, algo_alias_map[i][ ALIAS ] ) )
    {
      // found valid alias, return proper name
      *algo_or_alias = algo_alias_map[i][ PROPER ];
      return;
    }
}

