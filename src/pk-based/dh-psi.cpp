/*
 * dh-psi.cpp
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */
#include "dh-psi.h"

uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}


uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, uint32_t* matches, bool cardinality, field_type ftype) {

	uint32_t i, hash_bytes = crypt_env->get_hash_bytes(), intersect_size, fe_bytes, sndbufsize, rcvbufsize;
	//task_ctx ectx;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent = field->get_rnd_num();
	CSocket* tmpsock = sock;

	fe_bytes = field->fe_byte_size();

	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* cardinality_perm = (uint32_t*) malloc(sizeof(uint32_t) * pneles);
	//uint8_t* permeles = (uint8_t*) malloc(sizeof(uint8_t) * neles * elebytelen);
	uint8_t* encrypted_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);
	uint8_t* hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	//Partner's elements and hashes
	uint8_t *peles, *phashes, *perm_peles;


	/* Generate a random permutation for the elements */
	crypt_env->gen_rnd_perm(perm, neles);

	/* Hash elements */
	ectx.eles.output = hashes;
	ectx.eles.nelements = neles;
	ectx.eles.outbytelen = hash_bytes;
	ectx.eles.perm = perm;
	ectx.sctx.symcrypt = crypt_env;


#ifdef DEBUG
	cout << "Hashing elements" << endl;
#endif
	run_task(ntasks, ectx, psi_hashing_function);

	/* Encrypt elements */
	ectx.eles.input1d = hashes;
	ectx.eles.fixedbytelen = hash_bytes;
	ectx.eles.nelements = neles;
	ectx.eles.outbytelen = fe_bytes;
	ectx.eles.output = encrypted_eles;
	ectx.eles.hasvarbytelen = false;
	ectx.actx.field = field;
	ectx.actx.exponent = exponent;
	ectx.actx.sample = true;

#ifdef DEBUG
	cout << "Hash and encrypting my elements" << endl;
#endif
	run_task(ntasks, ectx, asym_encrypt);


	peles = (uint8_t*) malloc(sizeof(uint8_t) * pneles * fe_bytes);
#ifdef DEBUG
	cout << "Exchanging ciphertexts" << endl;
#endif
	snd_and_rcv(encrypted_eles, neles * fe_bytes, peles, pneles * fe_bytes, tmpsock);


	/* Import and Encrypt elements again */
	ectx.eles.input1d = peles;
	ectx.eles.output = peles;
	ectx.eles.nelements = pneles;
	ectx.eles.fixedbytelen = fe_bytes;
	ectx.eles.outbytelen = fe_bytes;
	ectx.eles.hasvarbytelen = false;
	ectx.actx.exponent = exponent;
	ectx.actx.sample = false;

#ifdef DEBUG
	cout << "Encrypting partners elements" << endl;
#endif
	run_task(ntasks, ectx, asym_encrypt);

	/* if only the cardinality should be computed, permute the elements randomly again. Otherwise don't permute */
	if(cardinality) {
		crypt_env->gen_rnd_perm(cardinality_perm, pneles);
	} else {
		for(i = 0; i < pneles; i++)
			cardinality_perm[i] = i;
	}

	/* Hash elements */
	phashes = (uint8_t*) malloc(sizeof(uint8_t) * pneles * hash_bytes);

	ectx.eles.input1d = peles;
	ectx.eles.output = phashes;
	ectx.eles.nelements = pneles;
	ectx.eles.fixedbytelen= fe_bytes;
	ectx.eles.outbytelen = hash_bytes;
	ectx.eles.hasvarbytelen = false;
	ectx.eles.perm = cardinality_perm;
	ectx.sctx.symcrypt = crypt_env;

#ifdef DEBUG
	cout << "Hashing elements" << endl;
#endif
	run_task(ntasks, ectx, psi_hashing_function);

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
		intersect_size = find_intersection(hashes, neles, phashes, pneles, hash_bytes, perm, matches);
	}

#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
	free(perm);
	free(encrypted_eles);
	free(hashes);
	free(peles);
	free(phashes);
	free(cardinality_perm);

	return intersect_size;
}
