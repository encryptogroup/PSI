/*
 * ot-psi.cpp
 *
 *  Created on: Jul 16, 2014
 *      Author: mzohner
 */

#include "ot-psi.h"


uint32_t otpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** res_bytelen, crypto* crypt_env, CSocket* sock,  uint32_t ntasks, double epsilon,
		bool detailed_timings) {

	prf_state_ctx prf_state;
	uint32_t maskbytelen, nbins, intersect_size, internal_bitlen, maskbitlen, *res_pos, i, elebytelen;
	uint8_t *eleptr;
	timeval t_start, t_end;


	DETAILED_TIMINGS = (detailed_timings>0);


	maskbitlen = pad_to_multiple(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
	maskbytelen = ceil_divide(maskbitlen, 8);

	//Hash elements into a smaller domain
	eleptr = (uint8_t*) malloc(maskbytelen * neles);

	//cout << "Hashing " << neles << " elements with arbitrary bit-length into " <<
	//		maskbitlen << " bit representation " << endl;

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}
	domain_hashing(neles, elements, elebytelens, eleptr, maskbytelen, crypt_env);
	internal_bitlen = maskbitlen;

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for domain hashing:\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end) << " ms" << endl;
	}

	crypt_env->gen_common_seed(&prf_state, sock[0]);

	if(role == SERVER) {
		nbins = ceil(epsilon * pneles);
		otpsi_server(eleptr, neles, nbins, pneles, internal_bitlen, maskbitlen, crypt_env, sock, ntasks,
				&prf_state);
	} else { //playing as client
		nbins = ceil(epsilon * neles);
		intersect_size = otpsi_client(eleptr, neles, nbins, pneles, internal_bitlen, maskbitlen, crypt_env,
				sock, ntasks, &prf_state, &res_pos);

		create_result_from_matches_var_bitlen(result, res_bytelen, elebytelens, elements, res_pos, intersect_size);
	}

	free(eleptr);

	return intersect_size;
}



uint32_t otpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock,  uint32_t ntasks, double epsilon,
		bool detailed_timings) {

	prf_state_ctx prf_state;
	uint32_t maskbytelen, nbins, intersect_size, internal_bitlen, maskbitlen, *res_pos, i, elebitlen;
	uint8_t *eleptr;
	timeval t_start, t_end;

	DETAILED_TIMINGS = detailed_timings;

	maskbitlen = pad_to_multiple(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
	maskbytelen = ceil_divide(maskbitlen, 8);
	elebitlen = elebytelen * 8;

	if(elebitlen > maskbitlen) {
		//Hash elements into a smaller domain
		eleptr = (uint8_t*) malloc(maskbytelen * neles);
		domain_hashing(neles, elements, elebytelen, eleptr, maskbytelen, crypt_env);
		internal_bitlen = maskbitlen;
#ifndef BATCH
		cout << "Hashing " << neles << " elements with " << elebitlen << " bit-length into " <<
				maskbitlen << " bit representation " << endl;
#endif
	} else {
		eleptr = elements;
		internal_bitlen = elebitlen;
	}

	crypt_env->gen_common_seed(&prf_state, sock[0]);

	if(role == SERVER) {
		nbins = ceil(epsilon * pneles);
		otpsi_server(eleptr, neles, nbins, pneles, internal_bitlen, maskbitlen, crypt_env, sock, ntasks,
				&prf_state);
	} else { //playing as client
		nbins = ceil(epsilon * neles);
		intersect_size = otpsi_client(eleptr, neles, nbins, pneles, internal_bitlen, maskbitlen, crypt_env,
				sock, ntasks, &prf_state, &res_pos);
		//*result = (uint8_t*) malloc(intersect_size * elebytelen);
		//for(i = 0; i < intersect_size; i++) {
		//	memcpy((*result) + i * elebytelen, elements + res_pos[i] * elebytelen, elebytelen);
		//}
		create_result_from_matches_fixed_bitlen(result, elebytelen, elements, res_pos, intersect_size);
	}

	if(elebitlen > maskbitlen)
		free(eleptr);

	return intersect_size;
}



uint32_t otpsi_client(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles,
		uint32_t elebitlen, uint32_t maskbitlen, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		prf_state_ctx* prf_state, uint32_t** result) {

	uint32_t outbitlen, maskbytelen, intersect_size;
	uint8_t *hash_table, *masks;
	uint32_t* nelesinbin;
	uint8_t *server_masks;
	uint32_t* perm = (uint32_t*) calloc(neles, sizeof(uint32_t));
	pthread_t rcv_masks_thread;
	pthread_t* query_map_thread = (pthread_t*) malloc(sizeof(pthread_t) * ntasks);
	query_ctx* query_data = (query_ctx*) malloc(sizeof(query_ctx) * ntasks);
	mask_rcv_ctx rcv_ctx;
	timeval t_start, t_end;
	uint32_t stashsize = get_stash_size(neles);

	nelesinbin = (uint32_t*) calloc(nbins, sizeof(uint32_t));
	maskbytelen = ceil_divide(maskbitlen, 8);
	intersect_size=0;

#ifdef TIMING
	gettimeofday(&t_start, NULL);
#endif
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}
#ifndef TEST_UTILIZATION
	hash_table = cuckoo_hashing(elements, neles, nbins, elebitlen, &outbitlen,
			nelesinbin, perm, ntasks, prf_state);
#else
	cerr << "Test utilization is active, PSI protocol will not be working correctly!" << endl;
	cuckoo_hashing(elements, neles, nbins, elebitlen, &outbitlen,
				nelesinbin, perm, ntasks, prf_state);
#endif
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for Cuckoo hashing:\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}

#ifdef PRINT_CLIENT_MAPPING
	uint32_t elebytelen = ceil_divide(elebitlen, 8);
	uint32_t outbytelen = ceil_divide(outbitlen, 8);
	for(uint32_t i = 0, ctr = 0; i < nbins; i++) {
		if(nelesinbin[i] > 0) {
			cout << "Element " << perm[ctr] << " " ;
			for(uint32_t j = 0; j < elebytelen; j++) {
				cout << (hex) << (uint32_t) elements[perm[ctr]*elebytelen + j] << (dec);
			}
			cout << " now maps to ";
			for(uint32_t j = 0; j < outbytelen; j++) {
				cout << (hex) << (uint32_t) hash_table[i*outbytelen + j] << (dec);
			}
			cout << endl;
			ctr++;
		}
	}
#endif

#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Client: time for cuckoo hashing: " << getMillies(t_start, t_end) << " ms" << endl;
	gettimeofday(&t_start, NULL);
#endif
#ifdef PRINT_BIN_CONTENT
	cout << "Client bin content: " << endl;
	print_bin_content(hash_table, nbins, ceil_divide(outbitlen, 8), NULL, false);
#endif

	masks = (uint8_t*) malloc(neles * maskbytelen);
	//Perform the OPRG execution
	//cout << "otpsi client running ots" << endl;
	oprg_client(hash_table, nbins, neles, nelesinbin, outbitlen, maskbitlen, crypt_env, sock, ntasks, masks);

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}

#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Client: time for OPRG evaluation: " << getMillies(t_start, t_end) << " ms" << endl;
	gettimeofday(&t_start, NULL);

#endif
#ifdef PRINT_BIN_CONTENT
	cout << "Client masks: " << endl;
	print_bin_content(masks, neles, maskbytelen, NULL, false);
#endif
	//receive server masks
	server_masks = (uint8_t*) malloc(NUM_HASH_FUNCTIONS * pneles * maskbytelen);

	//receive_masks(server_masks, NUM_HASH_FUNCTIONS * neles, maskbytelen, sock[0]);
	//use a separate thread to receive the server's masks
	rcv_ctx.rcv_buf = server_masks;
	rcv_ctx.nmasks = NUM_HASH_FUNCTIONS * pneles;
	rcv_ctx.maskbytelen = maskbytelen;
	rcv_ctx.sock = sock;
	if(pthread_create(&rcv_masks_thread, NULL, receive_masks, (void*) (&rcv_ctx))) {
		cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
		exit(0);
	}
	//meanwhile generate the hash table
	//GHashTable* map = otpsi_create_hash_table(ceil_divide(inbitlen,8), masks, neles, maskbytelen, perm);
	//intersect_size = otpsi_find_intersection(eleptr, result, ceil_divide(inbitlen,8), masks, neles, server_masks,
	//		neles * NUM_HASH_FUNCTIONS, maskbytelen, perm);
	//wait for receiving thread
	if(pthread_join(rcv_masks_thread, NULL)) {
		cerr << "Error in joining pthread at cuckoo hashing!" << endl;
		exit(0);
	}

#ifdef ENABLE_STASH
	//receive the masks for the stash
	//cout << "allocating a stash of size " << pneles << " * " << maskbytelen << " * " << stashsize << endl;
	uint8_t* stashmasks = (uint8_t*) malloc(pneles * maskbytelen * stashsize);
	rcv_ctx.rcv_buf = server_masks;
	rcv_ctx.nmasks = stashsize * pneles;
	rcv_ctx.maskbytelen = maskbytelen;
	rcv_ctx.sock = sock;
	if(pthread_create(&rcv_masks_thread, NULL, receive_masks, (void*) (&rcv_ctx))) {
		cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
		exit(0);
	}
#endif

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for receiving masks:\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}
#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Client: time for receiving masks and generating hash table: " << getMillies(t_start, t_end) << " ms" << endl;
	gettimeofday(&t_start, NULL);
#endif
#ifdef PRINT_RECEIVED_VALUES
	cout << "Received server masks: " << endl;
	print_bin_content(server_masks, NUM_HASH_FUNCTIONS*pneles, maskbytelen, NULL, false);
#endif

	//query hash table using multiple threads
	//TODO set the values in the struct correct
	/*for(i = 0; i < ntasks; i++) {
		neles_per_thread = i * ceil_divide(pneles, ntasks);
		thread_startpos = i * neles_per_thread;
		query_data[i].elebytelen = ceil_divide(inbitlen,8);
		query_data[i].elements = eleptr;
		query_data[i].hashbytelen = maskbytelen;
		query_data[i].map = map;
		query_data[i].qhashes = server_masks + (thread_startpos * NUM_HASH_FUNCTIONS * maskbytelen);
		query_data[i].qneles = min(neles - thread_startpos, neles_per_thread) * NUM_HASH_FUNCTIONS;//neles * NUM_HASH_FUNCTIONS;
		if(pthread_create(query_map_thread+i, NULL, otpsi_query_hash_table, (void*) (query_data+i))) {
			cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
			exit(0);
		}
	}*/
#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Client: time for computing intersection: " << getMillies(t_start, t_end) << " ms" << endl;
#endif

	//compute intersection
	intersect_size = otpsi_find_intersection(result, masks, neles, server_masks,
			pneles * NUM_HASH_FUNCTIONS, maskbytelen, perm);

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for intersecting:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
	}

	/*free(masks);
	free(hash_table);
	free(nelesinbin);
	free(perm);
	free(server_masks);
	free(query_map_thread);
	free(query_data);*/


	//cout << "joining" << endl;
	//meanwhile generate the hash table
	//GHashTable* map = otpsi_create_hash_table(ceil_divide(inbitlen,8), masks, neles, maskbytelen, perm);
	//intersect_size = otpsi_find_intersection(eleptr, result, ceil_divide(inbitlen,8), masks, neles, server_masks,
	//		neles * NUM_HASH_FUNCTIONS, maskbytelen, perm);
#ifdef ENABLE_STASH
	//wait for receiving thread
	if(pthread_join(rcv_masks_thread, NULL)) {
		cerr << "Error in joining pthread at cuckoo hashing!" << endl;
		exit(0);
	}
	free(stashmasks);
#endif

	return intersect_size;
}



void otpsi_server(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles, uint32_t elebitlen, uint32_t maskbitlen,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, prf_state_ctx* prf_state) {
	uint8_t *hash_table, *masks;
	uint32_t* nelesinbin;
	uint32_t outbitlen, maskbytelen;
	timeval t_start, t_end;
#ifdef ENABLE_STASH
	uint32_t stashsize = get_stash_size(neles);
#endif

	nelesinbin = (uint32_t*) malloc(sizeof(uint32_t) * nbins);
	maskbytelen = ceil_divide(maskbitlen, 8);

	//outbitlen = getOutBitLen(inbitlen, nbins);//bitlen - addr_bits;

	//hash_table = (uint8_t*) malloc(nbins * NUM_HASH_FUNCTIONS * ceil_divide(outbitlen, 8));
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}
#ifdef TIMING
	gettimeofday(&t_start, NULL);
#endif
	hash_table = simple_hashing(elements, neles, elebitlen, &outbitlen, nelesinbin, nbins, ntasks, prf_state);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for simple hashing:\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}
#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Server: time for simple hashing: " << getMillies(t_start, t_end) << " ms" << endl;
	gettimeofday(&t_start, NULL);
#endif
#ifdef PRINT_BIN_CONTENT
	print_bin_content(hash_table, nbins, ceil_divide(outbitlen, 8), nelesinbin, true);
#endif
	masks = (uint8_t*) malloc(NUM_HASH_FUNCTIONS * neles * maskbytelen);
	oprg_server(hash_table, nbins, neles * NUM_HASH_FUNCTIONS, nelesinbin, outbitlen, maskbitlen, crypt_env, sock, ntasks, masks);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}
#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Server: time for OPRG evaluation: " << getMillies(t_start, t_end) << " ms" << endl;
	gettimeofday(&t_start, NULL);
#endif
	//send the masks to the receiver
	send_masks(masks, neles * NUM_HASH_FUNCTIONS, maskbytelen, sock[0]);


#ifdef ENABLE_STASH
	//TODO: implement correctly
	//send masks for all items on the stash
	for(uint32_t i = 0; i < stashsize; i++) {
		send_masks(masks, neles, maskbytelen, sock[0]);
	}
#endif

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for sending masks:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
	}
#ifdef TIMING
	gettimeofday(&t_end, NULL);
	cout << "Server: time for sending masks: " << getMillies(t_start, t_end) << " ms" << endl;
#endif

	free(masks);
	free(hash_table);
	free(nelesinbin);
}

void oprg_client(uint8_t* hash_table, uint32_t nbins, uint32_t neles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt,	CSocket* sock, uint32_t nthreads, uint8_t* res_buf) {
	CBitVector choices;
	CBitVector resulting_masks;
	uint32_t OTsPerElement, numOTs, i, u, maskbytelen, ctr;
	uint8_t *keyMtx;
	OTExtension1ooNECCReceiver* receiver;
	timeval t_start, t_end;

	maskbytelen = ceil_divide(maskbitlen, 8);

	OTsPerElement = ceil_divide(elebitlen, 8);
	numOTs = nbins * OTsPerElement;

#ifndef BATCH
	cout << "Client: bins = " << nbins << ", elebitlen = " << elebitlen << " and maskbitlen = " <<
			maskbitlen << " and performs " << numOTs << " OTs" << endl;
#endif

	keyMtx = (uint8_t*) malloc(crypt->get_aes_key_bytes()*m_nCodeWordBits* 2);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}

	InitOTReceiver(keyMtx, sock[0], crypt);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for base-OTs:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}

	receiver = new OTExtension1ooNECCReceiver(m_nCodeWordBits, crypt, sock, keyMtx);

	//TODO recheck size
	choices.AttachBuf(hash_table, ceil_divide(numOTs * 8, 8));

	//for(uint32_t i = 0; i < nbins; i++) {
	resulting_masks.AttachBuf(res_buf, neles * maskbytelen);//[i].Create(maskbitlen);
	resulting_masks.Reset();
	//}

	//cout << "Choices: ";
	//choices.PrintHex();

	CBitVector response;
	response.Create(numOTs, AES_BITS);

	//uint32_t itembitlen, uint32_t maskbitlen, CBitVector* results, crypto* crypt
	//m_fMaskFct = new XORMasking(bitlength, m_cCrypto);
	OPEMasking* mskfct = new OPEMasking(elebitlen, maskbitlen, nbins, nelesinbin, resulting_masks, crypt);
	//choices.Reset();

//	ObliviouslyReceive(choices, response, numOTs, AES_BITS, RN_OT);
	//cout << "Receiver performing " << numOTs << " ots" << endl;
	receiver->receive(numOTs, AES_BITS, choices, response, RN_OT, nthreads, mskfct);

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for OT extension:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}

#ifdef PRINT_OPRG_MASKS
	for(i = 0, ctr=0; i < nbins; i++) {
		if(nelesinbin[i] > 0) {
			cout << "Result for element i = " << i << " and choice = ";// << (hex) <<
			for(uint32_t j = 0; j < OTsPerElement; j++) {
				//cout << (hex) << (uint32_t) hash_table[j + i * OTsPerElement] << (dec);
				cout << setw(2) << setfill('0') << (hex) << (uint32_t) choices.GetByte(j + i * OTsPerElement) << (dec);
			}
			cout << ": ";

			//choices.Get<uint64_t>(i * OTsPerElement*8, OTsPerElement*8) << (dec) << ": ";
			for(uint32_t j  = 0; j < maskbytelen; j++) {
				cout << setw(2) << setfill('0') << (hex) << (uint32_t) res_buf[ctr * maskbytelen + j] << (dec);
			}
			cout << endl;
			ctr++;
			//resulting_masks[i].PrintHex();
		}
		//memcpy(res_buf_ptr, resulting_masks[i].GetArr(), maskbytelen);
	}
#endif


	evaluate_crf(res_buf, res_buf, neles, maskbytelen, crypt);

#ifdef PRINT_CRF_EVAL
	for(i = 0, ctr=0; i < nbins; i++) {
		if(nelesinbin[i] > 0) {
			cout << "CRF Result for element i = " << i << ": ";
			for(uint32_t j  = 0; j < maskbytelen; j++) {
				cout << setw(2) << setfill('0') << (hex) << (uint32_t) res_buf[ctr * maskbytelen + j] << (dec);
			}
			cout << endl;
			ctr++;
		}
	}
#endif

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for CRF evaluation:\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
	}

	delete mskfct;
}




void oprg_server(uint8_t* hash_table, uint32_t nbins, uint32_t totaleles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, CSocket* sock, uint32_t nthreads, uint8_t* res_buf) {
	CBitVector input, results;
	CBitVector baseOTchoices;
	uint8_t* keySeeds;
	uint32_t numOTs, OTsPerBin, i, maskbytelen;
	OTExtension1ooNECCSender* sender;
	timeval t_start, t_end;

	maskbytelen = maskbitlen / 8;

	OTsPerBin = ceil_divide(elebitlen, 8);
	numOTs = nbins * OTsPerBin;

#ifndef BATCH
	cout << "Server: bins = " << nbins << ", elebitlen = " << elebitlen << " and maskbitlen = " <<
			maskbitlen << " and performs " << numOTs << " OTs" << endl;
#endif

	baseOTchoices.Create(m_nCodeWordBits);
	crypt->gen_rnd(baseOTchoices.GetArr(), ceil_divide(m_nCodeWordBits, 8));

	keySeeds = (uint8_t*) malloc(crypt->get_aes_key_bytes()*m_nCodeWordBits);

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_start, NULL);
	}
	InitOTSender(keySeeds, baseOTchoices, sock[0], crypt);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for base-OTs:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}
	sender = new OTExtension1ooNECCSender(m_nCodeWordBits, crypt, sock, baseOTchoices, keySeeds);

	//Check base-OT seeds
	/*for(i = 0; i < m_nCodeWordBits; i++) {
			cout << "i = " << i << ": " << (hex) << ((uint64_t*) keySeeds)[(i*2)] << ((uint64_t*) keySeeds)[(i*2)+1] << (dec) << endl;
	}*/

	//for(uint32_t i = 0; i < nbins; i++) {
	input.AttachBuf(hash_table, totaleles * ceil_divide(elebitlen, 8));
	results.AttachBuf(res_buf, totaleles * maskbytelen);
	//input.Reset();
	results.Reset();
	//}

	CBitVector values[2];
	values[0].Create(numOTs * AES_BITS);
	values[1].Create(numOTs * AES_BITS);

	//m_fMaskFct = new XORMasking(bitlength, m_cCrypto);
	OPEMasking* mskfct = new OPEMasking(elebitlen, maskbitlen, nbins, nelesinbin, input, results, crypt);
	//cout << "Sender performing " << numOTs << " ots" << endl;
	sender->send(numOTs, AES_BITS, values, RN_OT, nthreads, mskfct);//ObliviouslySend(values, numOTs, AES_BITS, RN_OT);
	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for OT extension:\t\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
		gettimeofday(&t_start, NULL);
	}

#ifdef PRINT_OPRG_MASKS
	for(i = 0; i < totaleles; i++) {
		cout << "OPRG output for element i = " << i << " ";
		for(uint32_t j  = 0; j < OTsPerBin; j++) {
			cout << setw(2) << setfill('0') << (hex) << (uint32_t) hash_table[i * OTsPerBin + j] << (dec);
		}
		cout << ": ";
		for(uint32_t j  = 0; j < maskbytelen; j++) {
			cout << setw(2) << setfill('0') << (hex) << (uint32_t) res_buf[i * maskbytelen + j] << (dec);
		}
		cout << endl;
	}
#endif
		//memcpy(res_buf_ptr, results[i].GetArr(), maskbytelen * nelesinbin[i]);
		//res_buf_ptr+=maskbytelen * nelesinbin[i];

	//evaluate correlation robust function on the elements
	evaluate_crf(res_buf, res_buf, totaleles, maskbytelen, crypt);

#ifdef PRINT_CRF_EVAL
	for(i = 0; i < totaleles; i++) {
		cout << "CRF output for element i = " << i << ": ";
		for(uint32_t j  = 0; j < maskbytelen; j++) {
			cout << setw(2) << setfill('0') << (hex) << (uint32_t) res_buf[i * maskbytelen + j] << (dec);
		}
		cout << endl;
	}
#endif

	if(DETAILED_TIMINGS) {
		gettimeofday(&t_end, NULL);
		cout << "Time for CRF evaluation:\t" << fixed << std::setprecision(2) <<
				getMillies(t_start, t_end) << " ms" << endl;
	}

	delete mskfct;
}


void InitOTSender(uint8_t* keySeeds, CBitVector& choices, CSocket sock, crypto* crypt)
{
#ifdef TIMING
	timeval np_begin, np_end;
#endif

//	keySeeds = (uint8_t*) malloc(crypt->get_aes_key_bytes()*m_nCodeWordBits);
	NaorPinkas* bot = new NaorPinkas(crypt, ECC_FIELD);


#ifdef TIMING
	gettimeofday(&np_begin, NULL);
#endif

	uint32_t numbaseOTs = m_nCodeWordBits;
	uint8_t* pBuf = (uint8_t*) malloc(numbaseOTs * crypt->get_hash_bytes());

	bot->Receiver(2, numbaseOTs, choices, sock, pBuf);

	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(uint32_t i=0; i<numbaseOTs; i++ ) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(keySeeds + i * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx+=crypt->get_hash_bytes();
		//cout << i << ": " << (hex) << ((uint64_t*)keySeeds)[2*i] << ((uint64_t*)keySeeds)[2*i+1]<< (dec) << endl;
	}
	free(pBuf);

#ifdef TIMING
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif

}

void InitOTReceiver(uint8_t* keyMtx, CSocket sock, crypto* crypt)
{
#ifdef TIMING
	timeval np_begin, np_end;
#endif

	NaorPinkas* bot = new NaorPinkas(crypt, ECC_FIELD);//NaorPinkas(m_sSecLvl, m_aSeed);

#ifdef TIMING
	gettimeofday(&np_begin, NULL);
#endif

	uint32_t numbaseOTs = m_nCodeWordBits;
	// Execute NP receiver routine and obtain the key
	uint8_t* pBuf = (uint8_t*) malloc(crypt->get_hash_bytes() * numbaseOTs * 2);
	bot->Sender(2, numbaseOTs, sock, pBuf);

#ifdef AES256_HASH
	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(uint32_t i=0; i<numbaseOTs; i++ )
	{
		memcpy(keyMtx + i * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx += crypt->get_hash_bytes();
		memcpy(keyMtx + i * crypt->get_aes_key_bytes() + numbaseOTs * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx += crypt->get_hash_bytes();
	}
#else
	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(uint32_t i=0; i<numbaseOTs * 2; i++ )
	{
		memcpy(keyMtx + i * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx += crypt->get_hash_bytes();
	}
#endif

	free(pBuf);


#ifdef TIMING
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif
}


void send_masks(uint8_t* masks, uint32_t nmasks, uint32_t maskbytelen, CSocket& sock) {
	sock.Send(masks, nmasks*maskbytelen);
}


void receive_masks(uint8_t* masks, uint32_t nmasks, uint32_t maskbytelen, CSocket& sock) {
	sock.Receive(masks, nmasks*maskbytelen);
}


GHashTable* otpsi_create_hash_table(uint32_t elebytelen, uint8_t* hashes, uint32_t neles, uint32_t
		hashbytelen, uint32_t* perm) {
	uint64_t tmpbuf;
	uint32_t i, tmp_hashbytelen;

	tmp_hashbytelen = min((uint32_t) sizeof(uint64_t), hashbytelen);

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < neles; i++) {
		memcpy((uint8_t*) &tmpbuf, hashes + i*tmp_hashbytelen, tmp_hashbytelen);
		g_hash_table_insert(map,(void*) &tmpbuf, &(perm[i]));
	}
	return map;
}


void *otpsi_query_hash_table(void* ctx_tmp) {//GHashTable *map, uint8_t* elements, uint8_t** result, uint32_t elebytelen,
		//uint8_t* qhashes, uint32_t qneles, uint32_t hashbytelen) {

	cout << "Starting to query hash table" << endl;
	query_ctx* qctx = (query_ctx*) ctx_tmp;

	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * qctx->qneles);
	uint32_t* tmpval;
	GHashTable *map = qctx->map;
	uint8_t* qhashes = qctx->qhashes;
	uint8_t* elements = qctx->elements;
	uint64_t tmpbuf;

	uint32_t size_intersect, i, intersect_ctr, tmp_hashbytelen, elebytelen;
	elebytelen = qctx->elebytelen;

	tmp_hashbytelen = min((uint32_t) sizeof(uint64_t), qctx->hashbytelen);

	for(i = 0, intersect_ctr = 0; i < qctx->qneles; i++) {
		memcpy((uint8_t*) &tmpbuf, qhashes + i*tmp_hashbytelen, tmp_hashbytelen);
		if(g_hash_table_lookup_extended(map, (void*) &tmpbuf, NULL, (void**) &tmpval)) {
			matches[intersect_ctr] = tmpval[0];
			intersect_ctr++;
		}
	}

	size_intersect = intersect_ctr;

	qctx->result = (uint8_t*) malloc(sizeof(uint8_t) * size_intersect * elebytelen);
	for(i = 0; i < size_intersect; i++) {
		memcpy((qctx->result) + i * elebytelen, elements + matches[i] * elebytelen, elebytelen);
	}
	qctx->res_size = size_intersect;

	free(matches);
	//return size_intersect;
}

//TODO if this works correctly, combine with other find intersection methods and outsource to hashing_util.h
uint32_t otpsi_find_intersection(uint32_t** result, uint8_t* my_hashes,
		uint32_t my_neles, uint8_t* pa_hashes, uint32_t pa_neles, uint32_t hashbytelen, uint32_t* perm) {

	uint32_t keys_stored;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * my_neles);
	uint32_t* tmpval;
	uint64_t tmpbuf;
	uint32_t* tmpkeys;
	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * my_neles);

	for(uint32_t i = 0; i < my_neles; i++) {
		assert(perm[i] < my_neles);
		invperm[perm[i]] = i;
	}

	uint32_t size_intersect, i, intersect_ctr, tmp_hashbytelen;

	//tmp_hashbytelen; //= min((uint32_t) sizeof(uint64_t), hashbytelen);
	if(sizeof(uint64_t) < hashbytelen) {
		keys_stored = 2;
		tmp_hashbytelen = sizeof(uint64_t);
		tmpkeys = (uint32_t*) calloc(my_neles * keys_stored, sizeof(uint32_t));
		for(i = 0; i < my_neles; i++) {
			memcpy(tmpkeys + 2*i,  my_hashes + i*hashbytelen + tmp_hashbytelen, hashbytelen-sizeof(uint64_t));
			memcpy(tmpkeys + 2*i + 1, perm + i, sizeof(uint32_t));
		}
	} else {
		keys_stored = 1;
		tmp_hashbytelen = hashbytelen;
		tmpkeys = (uint32_t*) malloc(my_neles * sizeof(uint32_t));
		memcpy(tmpkeys, perm, my_neles * sizeof(uint32_t));
	}

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < my_neles; i++) {
		tmpbuf=0;
		memcpy((uint8_t*) &tmpbuf, my_hashes + i*hashbytelen, tmp_hashbytelen);
		//cout << "Insertion, " << i << " = " <<(hex) << tmpbuf << endl;
		//for(uint32_t j = 0; j < tmp_hashbytelen; j++)

		g_hash_table_insert(map,(void*) &tmpbuf, &(tmpkeys[i*keys_stored]));
	}

	for(i = 0, intersect_ctr = 0; i < pa_neles; i++) {
		//tmpbuf=0;
		memcpy((uint8_t*) &tmpbuf, pa_hashes + i*hashbytelen, tmp_hashbytelen);
		//cout << "Query, " << i << " = " <<(hex) << tmpbuf << (dec) << endl;
		if(g_hash_table_lookup_extended(map, (void*) &tmpbuf, NULL, (void**) &tmpval)) {
			if(keys_stored > 1) {
				tmpbuf = 0;
				memcpy((uint8_t*) &tmpbuf, pa_hashes + i*hashbytelen+sizeof(uint64_t), hashbytelen-sizeof(uint64_t));
				if((uint32_t) tmpbuf == tmpval[0]) {
					matches[intersect_ctr] = tmpval[1];
					if(intersect_ctr<my_neles)
						intersect_ctr++;
				//cout << "Match found at " << tmpval[0] << endl;
				}
			} else {
				//cout << "I have found a match for mask " << (hex) << tmpbuf << (dec) << endl;
				matches[intersect_ctr] = tmpval[0];
				//cout << "intersection found at position " << tmpval[0] << " for key " << (hex) << tmpbuf << (dec) << endl;
				if(intersect_ctr<my_neles)
					intersect_ctr++;
				//cout << "Match found at " << tmpval[0] << " for i = " << i << endl;
			}


		}
	}
	//cout << "Number of matches: " << intersect_ctr << ", my neles: " << my_neles << ", hashbytelen = " << hashbytelen << endl;
	assert(intersect_ctr <= my_neles);
	/*if(intersect_ctr > my_neles) {
		cerr << "more intersections than elements: " << intersect_ctr << " vs " << my_neles << endl;
		intersect_ctr = my_neles;
	}*/
	size_intersect = intersect_ctr;

	(*result) = (uint32_t*) malloc(sizeof(uint32_t) * size_intersect);
	memcpy(*result, matches, sizeof(uint32_t) * size_intersect);

	//cout << "I found " << size_intersect << " intersecting elements" << endl;

	free(matches);
	free(invperm);
	free(tmpkeys);
	return size_intersect;
}

void evaluate_crf(uint8_t* result, uint8_t* masks, uint32_t nelements, uint32_t elebytelen, crypto* crypt) {
	uint32_t i;
	AES_KEY_CTX aes_key;
	crypt->init_aes_key(&aes_key, 128, (uint8_t*) const_seed);
	for(i = 0; i < nelements; i++) {
		crypt->fixed_key_aes_hash(&aes_key, result+i*elebytelen, elebytelen, masks+i*elebytelen, elebytelen);
	}
}



void print_bin_content(uint8_t* hash_table, uint32_t nbins, uint32_t elebytelen, uint32_t* nelesinbin, bool multi_values) {
	uint32_t i, j, k, ctr;
	if(multi_values) {
		for(i = 0, ctr = 0; i < nbins; i++) {
			cout << "(" << nelesinbin[i] << ") Bin " << i << ": ";
			for(j = 0; j < nelesinbin[i]; j++) {
				for(k = 0; k < elebytelen; k++, ctr++) {
					cout << setw(2) << setfill('0') << (hex) << (unsigned int) hash_table[ctr] << (dec);
				}
				cout << " ";
			}
			cout << endl;
		}
	} else {
		for(i = 0, ctr = 0; i < nbins; i++) {
			cout << "Bin " << i << ": ";
			for(k = 0; k < elebytelen; k++, ctr++) {
				cout << setw(2) << setfill('0') << (hex) << (unsigned int) hash_table[ctr] << (dec);
			}
			cout << endl;
		}
		cout << endl;
	}
}

void *receive_masks(void *ctx_tmp) {
	mask_rcv_ctx* ctx = (mask_rcv_ctx*) ctx_tmp;
	ctx->sock->Receive(ctx->rcv_buf, ctx->maskbytelen * ctx->nmasks);
}

uint32_t get_stash_size(uint32_t neles) {
	if(neles >= (1<<24))
		return 2;
	if(neles >= (1<<20))
		return 3;
	if(neles >= (1<<16))
		return 4;
	if(neles >= (1<<12))
		return 6;
	if(neles >= (1<<8))
		return 12;
}
