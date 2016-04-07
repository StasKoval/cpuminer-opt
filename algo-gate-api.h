#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "miner.h"

/////////////////////////////
////
////    NEW FEATURE: algo_gate
////
////    algos define targets for their common functions
////    and define a function for miner-thread to call to register
////    their targets. miner thread builds the gate, and array of structs
////    of function pointers, by calling each algo's register function.
//
//
// 
//    So you want to add an algo. Well it is a little easier now.
//    Look at existing algos for guidance.
//
//    1. Define the algo, miner.h, previously in cpu-miner.c
//
//    2.Define custom versions of the mandatory function for the new algo.
//
//    3. Next look through the list of unsafe functions to determine
//    if any apply to the new algo. If so they must also be defined.
//
//    4. Look through the list of safe functions to see if any apply
//    to the new algo. If so look at the null instance of the function
//    to see if it satisfies its needs.
//
//    5. If any of the default safe functions are not fit for the new algo
//    a custom function will have to be defined.
//
//    6. Determine if other non existant functions are required.
//    That is determined by the need to add code in cpu-miner.c
//    that applies only to the new algo. That is forbidden. All
//    algo specific code must be in theh algo's file.
//
//    7. If new functions need to be added to the gate add the type
//    to the structure, declare a null instance in this file and define
//    it in algo-gate-api.c. It must be a safe optional function so the null
//    instance must return a success code and otherwise do nothing.
//
//    8. When all the custom functions are defined write a registration
//    function to initialze the gate's function pointers with the custom
//    functions. It is not necessary to initialze safe optional null
//    instances as they are defined by default, or unsafe functions that
//    are not needed by the algo.
//
//    9. Add an case entry to the switch/case in function register_gate
//    in file algo-gate-api.c for the new algo.
//
//    10 If a new function type was defined add an entry to ini talgo_gate
//    to initialize the new function to its null instance described in step 7.
//
//    11. If the new algo has aliases add them to the alias array in
//    algo-gate-api.c 
//
//    12. Include algo-gate-api.h and miner.h inthe algo's source file.
//
//    13. Inlude any other algo source files required by the new algo.
//
//    14. Done, compile and run. 


// declare some function pointers
// mandatory functions require a custom function specific to the algo
// be defined. 
// otherwise the null instance will return a fail code.
// Optional functions may not be required for certain algos or the null
// instance provides a safe default. If the default is suitable for
//  an algo it is not necessary to define a custom function.
//

typedef struct
{
//migrate to use work instead of pdata & ptarget, see decred for example.
// mandatory functions, must be overwritten
int   *( *scanhash ) ( int, struct work*, uint32_t, uint64_t*,
           unsigned char* );

// optional unsafe, must be overwritten if algo uses function
void   *( *hash )            ( void*, const void*, uint32_t ) ;
void   *( *hash_alt )        ( void*, const void*, uint32_t );
void   *( *hash_suw )        ( void*, const void*, uint32_t );
void   *( *init_ctx )        ();

//optional, safe to use default null instance

// regen_work for decred
bool   *( *ignore_pok )      ( int*, int*, int* );
// decode_extra_data for decred
void   *( *display_pok )     ( struct work*, uint64_t* );
void   *( *wait_for_diff )   ( struct stratum_ctx* );
double *( *get_max64 )       ();
void   *( *set_target)       ( struct work*, double );
bool   *( *get_scratchbuf )  ( unsigned char** );
//deprecated
bool   *( *use_rpc2 )        ();
void   *( *set_data_size )   ( uint32_t*, uint32_t*, struct work* );
int    *( *set_data_and_target_size )   ( int*, int*, int*, int*, bool* );
void   *( *gen_merkle_root        )  ( char*, struct stratum_ctx*, int*,
                                                      uint32_t*, int );
void   *( *build_stratum_request )  ( char*, struct work*, unsigned char*,
                                       char*, char* ); 
void   *( *reverse_endian )          ( struct work* );
// reverse_endian_34_35 for decred 
void   *( *reverse_endian_17_19 )    ( uint32_t*, uint32_t*, struct work* );
void   *( *calc_network_diff )       ( struct work* );
unsigned char*  *( *get_xnonce2str ) ( struct work*, size_t );
void   *( *set_benchmark_work_data ) ( struct work* );
void   *( *build_extraheader )       ( struct work*, struct stratum_ctx*,
                                       uint32_t*, int );
bool   *( *prevent_dupes )           ( uint32_t*, struct work*,
                                       struct stratum_ctx*, int );
void   *( *thread_barrier_init )    ();
void   *( *thread_barrier_wait )    ();
void   *( *copy_workdata )           ( struct work*, struct work*, uint32_t**,
                                       int, int, int, int );
void   ( *get_pseudo_random_data )  ( struct work*, char*, int );
} algo_gate_t;

// Declare null instances

// allways returns failure
int     null_scanhash ( int thr_id, struct work* work, uint32_t max_nonce,
              uint64_t *hashes_done, unsigned char* scratchbuf );

// just a stub that returns success
void    null_hash       ( void *output, const void *pdata, uint32_t len );
void    null_init_ctx   ();

// not truly null, but default, used to simplify algo registration by
// allowing algos to avoid needing to implement their own custom
// functions if the default works in their case.
void    null_gen_merkle_root( char*, struct stratum_ctx* sctx,
               int* headersize, uint32_t* extraheader, int extraheader_size );
void    null_wait_for_diff( struct stratum_ctx* stratum );
bool    null_ignore_pok ( int* wkcmp_sz, int* wkcmp_offset, int* nonce_oft );
void    null_display_pok ( struct work* work, uint64_t* net_blocks );
double  null_get_max64  ();
void    null_set_target ( struct work* work, double job_diff );
bool    null_get_scratchbuf( char** scratchbuf );
bool    null_use_rpc2   ();
void    null_set_data_size ( uint32_t* data_size, uint32_t* adata_sz );
void    null_set_data_and_target_size ( int *data_size, int *target_size,
                    int *adata_sz,  int *atarget_sz, bool* allow_mininginfo );
void    null_build_stratum_request( char* req, struct work* work,
               unsigned char *xnonce2str, char* ntimestr, char* noncestr );
void    null_reverse_endian( struct work* work );
void    null_reverse_endian_17_19( uint32_t* ntime , uint32_t* nonce,
                                    struct work* work );
void    null_calc_network_diff( struct work* work );
unsigned char*   null_get_xnonce2str( struct work* work, size_t xnonce1_size );
void    null_set_benchmark_work_data( struct work* work );
void    null_build_extraheader( struct work* work, struct stratum_ctx* sctx,
                                 uint32_t* extraheader, int headersize );
bool    null_prevent_dupes( uint32_t* nonceptr, struct work* work, 
                            struct stratum_ctx* stratum, int thr_id );
void    null_thread_barrier_init ();
void    null_thread_barrier_wait ();
void    null_copy_workdata ( struct work* work, struct work* g_work,
          uint32_t **nonceptr, int wkcmp_offset, int wkcmp_sz, int nonce_oft,
          int thr_id );
void    null_get_pseudo_random_data ( struct work*, char* scratchbuf,
                                       int thr_id );
char* null_get_nonce2str ( struct work* work );


bool register_algo( algo_gate_t *gate );

// use this to call the hash function of an algo directly
void exec_hash_function( int algo, void *output, const void *pdata );

void get_algo_alias( char** algo_or_alias );

