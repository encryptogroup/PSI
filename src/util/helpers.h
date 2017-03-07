/*
 * helpers.h
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#include "socket.h"
#include "typedefs.h"
#include "crypto/crypto.h"
#include "thread.h"
#include <glib.h>

struct element_ctx {
	uint32_t nelements;
	union {
		uint32_t fixedbytelen;
		uint32_t* varbytelens;
	};
	union {
		uint8_t* input1d;
		uint8_t** input2d;
	};
	uint32_t outbytelen;
	uint8_t* output;
	uint32_t* perm;
	uint32_t startelement;
	uint32_t endelement;
	bool hasvarbytelen;
};

struct sym_ctx {
	crypto* symcrypt;
	uint8_t* keydata;
};

struct asym_ctx {
	num* exponent;
	pk_crypto* field;
	bool sample;
};

struct task_ctx {
	element_ctx eles;
	union {
		sym_ctx sctx;
		asym_ctx actx;
	};
};

struct snd_ctx {
	uint8_t* snd_buf;
	uint32_t snd_bytes;
	CSocket* sock;
};


static uint32_t exchange_information(uint32_t myneles, uint32_t mybytelen, uint32_t mysecparam, uint32_t mynthreads,
		uint32_t myprotocol, CSocket& sock) {

	uint32_t pneles, pbytelen, psecparam, pnthreads, pprotocol;
	//Send own values
	sock.Send(&myneles, sizeof(uint32_t));
	sock.Send(&mybytelen, sizeof(uint32_t));
	sock.Send(&mysecparam, sizeof(uint32_t));
	sock.Send(&mynthreads, sizeof(uint32_t));
	sock.Send(&myprotocol, sizeof(uint32_t));

	//Receive partner values
	sock.Receive(&pneles, sizeof(uint32_t));
	sock.Receive(&pbytelen, sizeof(uint32_t));
	sock.Receive(&psecparam, sizeof(uint32_t));
	sock.Receive(&pnthreads, sizeof(uint32_t));
	sock.Receive(&pprotocol, sizeof(uint32_t));

	//Assert
	assert(mybytelen == pbytelen);
	assert(mysecparam == psecparam);
	assert(mynthreads == pnthreads);
	assert(myprotocol == pprotocol);

	return pneles;
}

static void create_result_from_matches_var_bitlen(uint8_t*** result, uint32_t** resbytelens, uint32_t* inbytelens,
		uint8_t** inputs, uint32_t* matches, uint32_t intersect_size) {
	uint32_t i;

	*result = (uint8_t**) malloc(sizeof(uint8_t*) * intersect_size);
	*resbytelens = (uint32_t*) malloc(sizeof(uint32_t) * intersect_size);

	std::sort(matches, matches+intersect_size);

	for(i = 0; i < intersect_size; i++) {
		//cout << "matches[" << i << "]: " << matches[i]  << endl;
		(*resbytelens)[i] = inbytelens[matches[i]];
		(*result)[i] = (uint8_t*) malloc((*resbytelens)[i]);
		memcpy((*result)[i], inputs[matches[i]], (*resbytelens)[i]);
	}
}

static void create_result_from_matches_fixed_bitlen(uint8_t** result, uint32_t inbytelen, uint8_t* inputs, uint32_t* matches,
		uint32_t intersect_size) {
	uint32_t i;
	*result = (uint8_t*) malloc(inbytelen * intersect_size);

	std::sort(matches, matches+intersect_size);

	for(i = 0; i < intersect_size; i++) {
		memcpy(*(result) + i * inbytelen, inputs + matches[i] * inbytelen, inbytelen);
	}
}

static void *asym_encrypt(void* context) {
#ifdef DEBUG
	cout << "Encryption task started" << endl;
#endif
	pk_crypto* field = ((task_ctx*) context)->actx.field;
	element_ctx electx = ((task_ctx*) context)->eles;
	num* e = ((task_ctx*) context)->actx.exponent;
	fe* tmpfe = field->get_fe();
	uint8_t *inptr=electx.input1d, *outptr=electx.output;
	uint32_t i;


	for(i = 0; i < electx.nelements; i++, inptr+=electx.fixedbytelen, outptr+=electx.outbytelen) {
		if(((task_ctx*) context)->actx.sample) {
			tmpfe->sample_fe_from_bytes(inptr, electx.fixedbytelen);
			//cout << "Mapped " << ((uint32_t*) inptr)[0] << " to ";
		} else {
			tmpfe->import_from_bytes(inptr);
		}
		tmpfe->set_pow(tmpfe, e);
		//tmpfe->print();
		tmpfe->export_to_bytes(outptr);
	}

	return 0;
}

static void *sym_encrypt(void* context) {
#ifdef DEBUG
	cout << "Hashing thread started" << endl;
#endif
	sym_ctx hdata = ((task_ctx*) context)->sctx;
	element_ctx electx = ((task_ctx*) context)->eles;

	crypto* crypt_env = hdata.symcrypt;

	AES_KEY_CTX aes_key;
	//cout << "initializing key" << endl;
	crypt_env->init_aes_key(&aes_key, hdata.keydata);
	//cout << "initialized key" << endl;

	uint8_t* aes_buf = (uint8_t*) malloc(AES_BYTES);
	uint32_t* perm = electx.perm;
	uint32_t i;

	if(electx.hasvarbytelen) {
		uint8_t **inptr = electx.input2d;
		for(i = electx.startelement; i < electx.endelement; i++) {
			//crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr[i], electx.varbytelens[i]);
			//cout << "encrypting i = " << i << ", perm = " << perm [i] << ", outbytelen = " << electx.outbytelen << endl;
			crypt_env->encrypt(&aes_key, aes_buf, inptr[i], electx.varbytelens[i]);
			memcpy(electx.output+perm[i]*electx.outbytelen, aes_buf, electx.outbytelen);
		}
	} else {
		uint8_t *inptr = electx.input1d;
		for(i = electx.startelement; i < electx.endelement; i++, inptr+=electx.fixedbytelen) {
			//crypt_env->hash(&aes_key, electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr, electx.fixedbytelen);
			crypt_env->encrypt(&aes_key, aes_buf, inptr, electx.fixedbytelen);
			memcpy(electx.output+perm[i]*electx.outbytelen, aes_buf, electx.outbytelen);
		}
	}

	//cout << "Returning" << endl;
	//free(aes_buf);
	return 0;
}

static void *psi_hashing_function(void* context) {
#ifdef DEBUG
	cout << "Hashing thread started" << endl;
#endif
	sym_ctx hdata = ((task_ctx*) context)->sctx;
	element_ctx electx = ((task_ctx*) context)->eles;

	crypto* crypt_env = hdata.symcrypt;

	uint32_t* perm = electx.perm;
	uint32_t i;
	uint8_t* tmphashbuf = (uint8_t*) malloc(crypt_env->get_hash_bytes());

	if(electx.hasvarbytelen) {
		uint8_t **inptr = electx.input2d;
		for(i = electx.startelement; i < electx.endelement; i++) {
			crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr[i], electx.varbytelens[i], tmphashbuf);
		}
	} else {
		uint8_t *inptr = electx.input1d;
		for(i = electx.startelement; i < electx.endelement; i++, inptr+=electx.fixedbytelen) {
			crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr, electx.fixedbytelen, tmphashbuf);
		}
	}
	free(tmphashbuf);
	return 0;
}

static void *send_data(void* context) {
	snd_ctx *ctx = (snd_ctx*) context;
	ctx->sock->Send(ctx->snd_buf, ctx->snd_bytes);
	return 0;
}


static void snd_and_rcv(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock) {
	pthread_t snd_task;
	bool created, joined;
	snd_ctx ctx;

	//Start new sender thread
	ctx.sock = sock;
	ctx.snd_buf = snd_buf;
	ctx.snd_bytes = snd_bytes;
	created = !pthread_create(&snd_task, NULL, send_data, (void*) &(ctx));

	//receive
	sock->Receive(rcv_buf, rcv_bytes);
	assert(created);

	joined = !pthread_join(snd_task, NULL);
	assert(joined);
}

static void run_task(uint32_t nthreads, task_ctx context, void* (*func)(void*) ) {
	task_ctx* contexts = (task_ctx*) malloc(sizeof(task_ctx) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.eles.nelements, nthreads);
	for(i = 0, electr = 0; i < nthreads; i++) {
		neles_cur = min(context.eles.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx));
		contexts[i].eles.nelements = neles_cur;
		contexts[i].eles.startelement = electr;
		contexts[i].eles.endelement = electr + neles_cur;
		electr += neles_cur;
	}

	for(i = 0; i < nthreads; i++) {
		created = !pthread_create(threads + i, NULL, func, (void*) &(contexts[i]));
	}

	assert(created);

	for(i = 0; i < nthreads; i++) {
		joined = !pthread_join(threads[i], NULL);
	}

	assert(joined);

	free(threads);
	free(contexts);
}




static uint32_t find_intersection(uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles,
		uint32_t hashbytelen, uint32_t* perm, uint32_t* matches) {

	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint64_t *tmpval, tmpkey = 0;
	uint32_t mapbytelen = min((uint32_t) hashbytelen, (uint32_t) sizeof(uint64_t));
	uint32_t size_intersect, i, intersect_ctr;

	for(i = 0; i < neles; i++) {
		invperm[perm[i]] = i;
	}

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < neles; i++) {
		memcpy(&tmpkey, hashes + i*hashbytelen, mapbytelen);
		g_hash_table_insert(map,(void*) &tmpkey, &(invperm[i]));
	}

	for(i = 0, intersect_ctr = 0; i < pneles; i++) {
		memcpy(&tmpkey, phashes+ i*hashbytelen, mapbytelen);
		if(g_hash_table_lookup_extended(map, (void*) &tmpkey, NULL, (void**) &tmpval)) {
			matches[intersect_ctr] = tmpval[0];
			intersect_ctr++;
			assert(intersect_ctr <= min(neles, pneles));
		}
	}

	size_intersect = intersect_ctr;

	free(invperm);
	return size_intersect;
}


#endif /* HELPERS_H_ */
