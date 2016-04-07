extern int scanhash_hodl( int thr_id, struct work* work, uint32_t max_nonce,
    uint64_t *hashes_done, unsigned char *mainMemoryPsuedoRandomData );

extern void GetPsuedoRandomData( char* mainMemoryPsuedoRandomData,
                  uint32_t *pdata, int thr_id );

void hodl_set_target( struct work* work, double diff );

bool hodl_get_scratchbuf( unsigned char** scratchbuf );

void hodl_thread_barrier_init();

void hodl_thread_barrier_wait();

void hodl_copy_workdata( struct work* work, struct work* g_work );

void hodl_get_pseudo_random_data( struct work* work, char* scratchbuf,
                                  int thr_id );

bool register_hodl_algo ( algo_gate_t* gate );


