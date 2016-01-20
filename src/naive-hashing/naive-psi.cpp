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
	uint8_t *hashes, *phashes;

	maskbytelen = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);

	hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	perm  = (uint32_t*) malloc(sizeof(uint32_t) * neles);


	/* Generate the random permutation the elements */
	crypt_env->gen_rnd_perm(perm, neles);

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
	ectx.sctx.symcrypt = crypt_env;

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
	//free(permeles);
	free(phashes);

	return intersect_size;
}


