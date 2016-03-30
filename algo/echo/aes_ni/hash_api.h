/*
 * file        : hash_api.h
 * version     : 1.0.208
 * date        : 14.12.2010
 * 
 * ECHO vperm implementation Hash API
 *
 * Cagdas Calik
 * ccalik@metu.edu.tr
 * Institute of Applied Mathematics, Middle East Technical University, Turkey.
 *
 */


#ifndef HASH_API_H
#define HASH_API_H

#ifndef NO_AES_NI
#define HASH_IMPL_STR	"ECHO-aesni"
#else
#define HASH_IMPL_STR	"ECHO-vperm"
#endif


#include "algo/sha3/sha3_common.h"

#include <emmintrin.h>


typedef struct
{
	__m128i			state[4][4];
	__m128i			k;
	__m128i			hashsize;
	__m128i			const1536;

	unsigned int	uRounds;
	unsigned int	uHashSize;
	unsigned int	uBlockLength;
	unsigned int	uBufferBytes;
	DataLength		processed_bits;
	BitSequence		buffer[192];

} hashState_echo;

// init non-zero constants, dynamic data inited in reinit_echo
static hashState_echo initial_echo512_ctx =
{
 0, 0,
 0,   //  _mm_set_epi32(0, 0, 0, 0x00000200), // hashsize 
 0,
 0,  // _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0x00000400),  //const1536
 10,   // uRounds
 512,  // uHashSize
 128,  // uBlockLength
};

HashReturn init_echo(hashState_echo *state, int hashbitlen);

HashReturn reinit_echo(hashState_echo *state);

HashReturn update_echo(hashState_echo *state, const BitSequence *data, DataLength databitlen);

HashReturn final_echo(hashState_echo *state, BitSequence *hashval);

HashReturn hash_echo(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);


#endif // HASH_API_H

