/*
 * naive-psi.cpp
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */
#include "naive-psi.h"

//routine for 2dimensional array with variable bit-length elements
uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = naivepsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches);

	create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

//routine for 1dimensional array with fixed bit-length elements
uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;

	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = naivepsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches);

	create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t naivepsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, uint32_t* matches) {

	uint32_t i, intersect_size, maskbytelen;
	//task_ctx_naive ectx;
	CSocket* tmpsock = sock;

	uint32_t* perm;
	uint8_t *permeles, *hashes, *phashes;

	maskbytelen = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);

	//permeles = (uint8_t*) malloc(sizeof(uint8_t) * neles * elebytelen);
	hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	perm  = (uint32_t*) malloc(sizeof(uint32_t) * neles);


	/* Generate the random permutation the elements */
	crypt_env->gen_rnd_perm(perm, neles);
	//for(i = 0; i < neles; i++) {
	//	memcpy(permeles + perm[i] * elebytelen,  elements + i * elebytelen, elebytelen);
	//}

	/* Hash and permute elements */
#ifdef DEBUG
	cout << "Hashing my elements" << endl;
#endif

	//ectx.eles.input = permeles;
	//ectx.eles.inbytelen = elebytelen;
	ectx.eles.outbytelen = maskbytelen,
	ectx.eles.nelements = neles;
	ectx.eles.output = hashes;
	ectx.eles.perm = perm;

	ectx.hctx.symcrypt = crypt_env;

	run_task(ntasks, ectx, hash);

	phashes = (uint8_t*) malloc(sizeof(uint8_t) * pneles * maskbytelen);


#ifdef DEBUG
	cout << "Exchanging hashes" << endl;
#endif
	snd_and_rcv(hashes, neles * maskbytelen, phashes, pneles * maskbytelen, tmpsock);

	/*cout << "Hashes of my elements: " << endl;
	for(i = 0; i < neles; i++) {
		for(uint32_t j = 0; j < maskbytelen; j++) {
			cout << (hex) << (uint32_t) hashes[i * maskbytelen + j] << (dec);
		}
		cout << endl;
	}

	cout << "Hashes of partner elements: " << endl;
	for(i = 0; i < pneles; i++) {
		for(uint32_t j = 0; j < maskbytelen; j++) {
			cout << (hex) << (uint32_t) phashes[i * maskbytelen + j] << (dec);
		}
		cout << endl;
	}*/
#ifdef DEBUG
	cout << "Finding intersection" << endl;
#endif
	intersect_size = find_intersection(hashes, neles, phashes, pneles, maskbytelen,
			perm, matches);


#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
	free(perm);
	free(hashes);
	free(permeles);
	free(phashes);

	return intersect_size;
}



/*uint32_t find_intersection_naive(uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles,
		uint32_t hashbytelen, uint32_t* perm, uint32_t* matches) {

	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	//uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint64_t* tmpval;

	uint32_t size_intersect, i, intersect_ctr;

	for(i = 0; i < neles; i++) {
		invperm[perm[i]] = i;
	}
	//cout << "My number of elements. " << neles << ", partner number of elements: " << pneles << ", maskbytelen: " << hashbytelen << endl;

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < neles; i++) {
		g_hash_table_insert(map,(void*) ((uint64_t*) &(hashes[i*hashbytelen])), &(invperm[i]));
	}

	//for(i = 0; i < pneles; i++) {
	//	((uint64_t*) &(phashes[i*hashbytelen]))[0]++;
	//}

	for(i = 0, intersect_ctr = 0; i < pneles; i++) {

		if(g_hash_table_lookup_extended(map, (void*) ((uint64_t*) &(phashes[i*hashbytelen])),
		    				NULL, (void**) &tmpval)) {
			matches[intersect_ctr] = tmpval[0];
			intersect_ctr++;
			assert(intersect_ctr <= min(neles, pneles));
		}
	}

	size_intersect = intersect_ctr;

	//result = (uint8_t**) malloc(sizeof(uint8_t*));
	//(*result) = (uint8_t*) malloc(sizeof(uint8_t) * size_intersect * elebytelen);
	//for(i = 0; i < size_intersect; i++) {
	//	memcpy((*result) + i * elebytelen, elements + matches[i] * elebytelen, elebytelen);
	//}

	free(invperm);
	//free(matches);
	return size_intersect;
}*/

/*void snd_and_rcv_naive(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock) {
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
}*/

/*void run_task_naive(uint32_t nthreads, task_ctx context, void* (*func)(void*) ) {

	task_ctx* contexts = (task_ctx*) malloc(sizeof(task_ctx) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.eles.nelements, nthreads);
	for(i = 0, electr = 0; i < nthreads; i++) {
		neles_cur = min(context.eles.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx));
		//contexts[i].eles.nelements = neles_cur;
		contexts[i].eles.startelement = electr;
		contexts[i].eles.endelement = electr + neles_cur;
		//contexts[i].eles.input = context.eles.input + (context.eles.inbytelen * electr);
		//contexts[i].eles.output = context.eles.output + (context.eles.outbytelen * electr);
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
}*/



/*void *send_data_naive(void* context) {
	snd_ctx_naive *ctx = (snd_ctx_naive*) context;
	ctx->sock->Send(ctx->snd_buf, ctx->snd_bytes);
	return 0;
}*/


