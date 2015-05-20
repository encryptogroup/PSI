/*
 * naive-psi.h
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */

#ifndef NAIVE_PSI_H_
#define NAIVE_PSI_H_


#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"



struct element_ctx_naive {
	uint32_t nelements;
	union {
		uint32_t fixed;
		uint32_t* var;
	} inbytelen;
	union {
		uint8_t* onedim;
		uint8_t** twodim;
	} inputs;
	uint32_t outbytelen;
	uint8_t* output;
	uint32_t* perm;
	bool varbytelen;
};

struct hash_ctx_naive {
	crypto* symcrypt;
	uint32_t startelement;
	uint32_t endelement;
};

struct task_ctx_naive {
	element_ctx_naive eles;
	hash_ctx_naive hctx;
};

struct snd_ctx_naive {
	uint8_t* snd_buf;
	uint32_t snd_bytes;
	CSocket* sock;
};

//TODO merge with dhpsi

void print_naive_psi_usage();
uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks);
uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks);
uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx_naive ectx,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, uint32_t* matches);

void run_task_naive(uint32_t nthreads, task_ctx_naive context, void* (*func)(void*) );
void permute_naive(uint32_t nelements, uint32_t bytelen, uint8_t* elements, uint8_t* result, uint32_t* perm);

uint32_t find_intersection_naive(uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles,
		uint32_t hashbytelen, uint32_t* perm, uint32_t* matches);

void snd_and_rcv_naive(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock);
void *hash_naive(void* context);
void *send_data_naive(void* context);





#endif /* NAIVE_PSI_H_ */
