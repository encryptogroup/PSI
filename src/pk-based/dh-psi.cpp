/*
 * dh-psi.cpp
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */
#include "dh-psi.h"

uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {

	uint32_t i, hash_bytes = crypt_env->get_hash_bytes(), intersect_size, fe_bytes, sndbufsize, rcvbufsize;
	task_ctx ectx;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent = field->get_rnd_num();
	CSocket* tmpsock = sock;

	fe_bytes = field->fe_byte_size();

	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* cardinality_perm;
	uint8_t* permeles = (uint8_t*) malloc(sizeof(uint8_t) * neles * elebytelen);
	uint8_t* encrypted_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);
	uint8_t* hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	//Partner's elements and hashes
	uint8_t *peles, *phashes, *perm_peles;


	/* Permute the elements */
	crypt_env->gen_rnd_perm(perm, neles);
	for(i = 0; i < neles; i++) {
		memcpy(permeles + perm[i] * elebytelen,  elements + i * elebytelen, elebytelen);
	}

	/* Hash elements */
	ectx.eles.input = permeles;
	ectx.eles.output = hashes;
	ectx.eles.nelements = neles;
	ectx.eles.inbytelen = elebytelen;
	ectx.eles.outbytelen = hash_bytes;
	ectx.hctx.symcrypt = crypt_env;

#ifdef DEBUG
	cout << "Hashing elements" << endl;
#endif
	run_task(ntasks, ectx, hash);

	/* Encrypt elements */
	ectx.eles.input = hashes;
	ectx.eles.inbytelen = hash_bytes;
	ectx.eles.nelements = neles;
	ectx.eles.outbytelen = fe_bytes;
	ectx.eles.output = encrypted_eles;
	ectx.ectx.field = field;
	ectx.ectx.exponent = exponent;
	ectx.ectx.sample = true;

#ifdef DEBUG
	cout << "Hash and encrypting my elements" << endl;
#endif
	run_task(ntasks, ectx, encrypt);


	peles = (uint8_t*) malloc(sizeof(uint8_t) * pneles * fe_bytes);
#ifdef DEBUG
	cout << "Exchanging ciphertexts" << endl;
#endif
	snd_and_rcv(encrypted_eles, neles * fe_bytes, peles, pneles * fe_bytes, tmpsock);


	if(cardinality) {
		//samle permutation, permute elements, and copy back to original array
		cardinality_perm = (uint32_t*) malloc(sizeof(uint32_t) * pneles);
		crypt_env->gen_rnd_perm(cardinality_perm, pneles);
		perm_peles = (uint8_t*) malloc(pneles * fe_bytes);
		for(i = 0; i < pneles; i++) {
			memcpy(perm_peles + cardinality_perm[i] * fe_bytes,  peles + i * fe_bytes, fe_bytes);
		}
		memcpy(peles, perm_peles, fe_bytes * pneles);
		free(cardinality_perm);
		free(perm_peles);
	}

	/* Import and Encrypt elements again */
	ectx.eles.input = peles;
	ectx.eles.output = peles;
	ectx.eles.nelements = pneles;
	ectx.eles.inbytelen = fe_bytes;
	ectx.eles.outbytelen = fe_bytes;
	ectx.ectx.exponent = exponent;
	ectx.ectx.sample = false;

#ifdef DEBUG
	cout << "Encrypting partners elements" << endl;
#endif
	run_task(ntasks, ectx, encrypt);

	/* Hash elements */
	phashes = (uint8_t*) malloc(sizeof(uint8_t) * pneles * hash_bytes);

	ectx.eles.input = peles;
	ectx.eles.output = phashes;
	ectx.eles.nelements = pneles;
	ectx.eles.inbytelen = fe_bytes;
	ectx.eles.outbytelen = hash_bytes;
	ectx.hctx.symcrypt = crypt_env;

#ifdef DEBUG
	cout << "Hashing elements" << endl;
#endif
	run_task(ntasks, ectx, hash);

#ifdef DEBUG
	cout << "Exchanging hashes" << endl;
#endif

	if(role == SERVER) {
		sndbufsize = pneles * hash_bytes;
		rcvbufsize = 0;
	} else {
		sndbufsize = 0;
		rcvbufsize = neles * hash_bytes;
	}

	snd_and_rcv(phashes, sndbufsize, hashes, rcvbufsize, tmpsock);

#ifdef DEBUG
	cout << "Finding intersection" << endl;
#endif
	if(role == SERVER) {
		intersect_size = 0;
	} else {
		intersect_size = find_intersection(elements, result, elebytelen, hashes,
				neles, phashes, pneles, hash_bytes, perm);
	}

#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
	free(perm);
	free(permeles);
	free(encrypted_eles);
	free(hashes);
	free(peles);
	free(phashes);

	return intersect_size;
}



uint32_t find_intersection(uint8_t* elements, uint8_t** result, uint32_t elebytelen, uint8_t* hashes,
		uint32_t neles, uint8_t* phashes, uint32_t npeles, uint32_t hashbytelen, uint32_t* perm) {

	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint64_t* tmpinbuf;
	uint64_t* tmpval;
	uint32_t size_intersect, i, intersect_ctr, nextrakeysstored, j;
	bool success;


	nextrakeysstored = ceil_divide(hashbytelen, sizeof(uint64_t))-1;
	cout << "hashbytelen = " << hashbytelen << ", nextrakeysstored = " << nextrakeysstored << endl;

	//store all the extra keys as well as the
	tmpinbuf = (uint64_t*) malloc(neles * (nextrakeysstored+1) * sizeof(uint64_t));

	for(i = 0; i < neles; i++) {
		memcpy(tmpinbuf + i * (nextrakeysstored+1), hashes + i * hashbytelen + sizeof(uint64_t),
				nextrakeysstored*sizeof(uint64_t));
		tmpinbuf[perm[i] * (nextrakeysstored+1) + nextrakeysstored] = (uint64_t) i;
		//invperm[perm[i]] = i;
	}


	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < neles; i++) {
	//	g_hash_table_insert(map,(void*) ((uint64_t*) &(hashes[i*hashbytelen])), &(invperm[i]));
		g_hash_table_insert(map,(void*) ((uint64_t*) &(hashes[i*hashbytelen])), &(tmpinbuf[i*(nextrakeysstored+1)]));
	}

	for(i = 0, intersect_ctr = 0; i < npeles; i++) {
		success = true;
		if(g_hash_table_lookup_extended(map, (void*) ((uint64_t*) &(phashes[i*hashbytelen])),
		    				NULL, (void**) &tmpval)) {
			for(j = 0; j < nextrakeysstored; j++) {
				if(((uint64_t*) &(phashes[i*hashbytelen]))[j+1] != tmpval[j]) {
					success = false;
				}
			}
			if(success) {
				matches[intersect_ctr] = tmpval[nextrakeysstored];
				intersect_ctr++;
			}
		}
	}

	size_intersect = intersect_ctr;

	//result = (uint8_t**) malloc(sizeof(uint8_t*));
	(*result) = (uint8_t*) malloc(sizeof(uint8_t) * size_intersect * elebytelen);
	for(i = 0; i < size_intersect; i++) {
		memcpy((*result) + i * elebytelen, elements + matches[i] * elebytelen, elebytelen);
	}

	free(invperm);
	free(matches);
	free(tmpinbuf);
	return size_intersect;
}

void snd_and_rcv(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock) {
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

void run_task(uint32_t nthreads, task_ctx context, void* (*func)(void*) ) {
	task_ctx* contexts = (task_ctx*) malloc(sizeof(task_ctx) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.eles.nelements, nthreads);
	for(i = 0, electr = 0; i < nthreads; i++) {
		neles_cur = min(context.eles.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx));
		contexts[i].eles.nelements = neles_cur;
		contexts[i].eles.input = context.eles.input + (context.eles.inbytelen * electr);
		contexts[i].eles.output = context.eles.output + (context.eles.outbytelen * electr);
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


void *encrypt(void* context) {
#ifdef DEBUG
	cout << "Encryption task started" << endl;
#endif
	pk_crypto* field = ((task_ctx*) context)->ectx.field;
	element_ctx electx = ((task_ctx*) context)->eles;
	num* e = ((task_ctx*) context)->ectx.exponent;
	fe* tmpfe = field->get_fe();
	uint8_t *inptr=electx.input, *outptr=electx.output;
	uint32_t i;


	for(i = 0; i < electx.nelements; i++, inptr+=electx.inbytelen, outptr+=electx.outbytelen) {
		if(((task_ctx*) context)->ectx.sample) {
			tmpfe->sample_fe_from_bytes(inptr, electx.inbytelen);
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

void *hash(void* context) {
#ifdef DEBUG
	cout << "Hashing thread started" << endl;
#endif
	crypto* crypt_env = ((task_ctx*) context)->hctx.symcrypt;
	element_ctx electx = ((task_ctx*) context)->eles;

	uint8_t *inptr=electx.input, *outptr=electx.output;
	uint32_t i;


	for(i = 0; i < electx.nelements; i++, inptr+=electx.inbytelen, outptr+=electx.outbytelen) {
		crypt_env->hash(outptr, electx.outbytelen, inptr, electx.inbytelen);
	}
	return 0;
}

void *send_data(void* context) {
	snd_ctx *ctx = (snd_ctx*) context;
	ctx->sock->Send(ctx->snd_buf, ctx->snd_bytes);
	return 0;
}




void print_dh_psi_usage() {
	cout << "Usage: ./dhpsi [0 (server)/1 (client)] [num_elements] " <<
			"[element_byte_length] [sym_security_bits] [server_ip] [server_port]" << endl;
	cout << "Program exiting" << endl;
	exit(0);
}
