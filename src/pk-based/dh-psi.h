/*
 * dh-psi.h
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */

#ifndef DH_PSI_H_
#define DH_PSI_H_


#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>


struct element_ctx {
	uint32_t nelements;
	uint32_t inbytelen;
	uint8_t* input;
	uint32_t outbytelen;
	uint8_t* output;
};

struct encrypt_ctx {
	num* exponent;
	pk_crypto* field;
	bool sample;
};

struct hash_ctx {
	crypto* symcrypt;
};

struct task_ctx {
	element_ctx eles;
	union {
		hash_ctx hctx;
		encrypt_ctx ectx;
	};
};

struct snd_ctx {
	uint8_t* snd_buf;
	uint32_t snd_bytes;
	CSocket* sock;
};


void print_dh_psi_usage();
uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality=false,
		field_type ftype=ECC_FIELD);
void run_task(uint32_t nthreads, task_ctx context, void* (*func)(void*) );
void permute(uint32_t nelements, uint32_t bytelen, uint8_t* elements, uint8_t* result, uint32_t* perm);
uint32_t find_intersection(uint8_t* elements, uint8_t** result, uint32_t elebytelen, uint8_t* hashes,
		uint32_t neles, uint8_t* phashes, uint32_t peles, uint32_t hashbytelen, uint32_t* perm);
void snd_and_rcv(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock);
void *encrypt(void* context);
void *hash(void* context);
void *send_data(void* context);





#endif /* DH_PSI_H_ */
