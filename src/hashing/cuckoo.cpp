/*
 * cuckoo.cpp
 *
 *  Created on: Oct 7, 2014
 *      Author: mzohner
 */

#include "cuckoo.h"

//returns a cuckoo hash table with the first dimension being the bins and the second dimension being the pointer to the elements
uint8_t* cuckoo_hashing(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t bitlen, uint32_t *outbitlen, uint32_t* nelesinbin,
		uint32_t* perm,	uint32_t ntasks, prf_state_ctx* prf_state)
{
	//The resulting hash table
	uint8_t* hash_table;
	cuckoo_entry_ctx** cuckoo_table;
	cuckoo_entry_ctx* cuckoo_entries;
	uint32_t i, j;
	uint32_t *perm_ptr;
	pthread_t* entry_gen_tasks;
	cuckoo_entry_gen_ctx* ctx;
	hs_t hs;

#ifdef COUNT_FAILS
	uint32_t fails = 0;
#endif


	init_hashing_state(&hs, neles, bitlen, nbins, prf_state);
	*outbitlen = hs.outbitlen;

	cuckoo_table = (cuckoo_entry_ctx**) calloc(nbins, sizeof(cuckoo_entry_ctx*));
	cuckoo_entries = (cuckoo_entry_ctx*) malloc(neles * sizeof(cuckoo_entry_ctx));
	entry_gen_tasks = (pthread_t*) malloc(sizeof(pthread_t) * ntasks);
	ctx = (cuckoo_entry_gen_ctx*) malloc(sizeof(cuckoo_entry_gen_ctx) * ntasks);

	//use the number of bins as address bits
	//addr_bits = ceil_log2(nbins);
	//cout << "Using addr_bits: " << hs.addrbitlen << endl;
	//cout << "number of bins: " << nbins << ", address bits = " << addr_bits << endl;
	//the remaining bits form the size of the values

	//inbytelen = ceil_divide(bitlen, 8);
	//outbytelen = ceil_divide(outbitlen, 8);
	//dummy_ele = (uint8_t*) malloc(ceil_divide(bitlen, 8));

	for(i = 0; i < ntasks; i++) {
		ctx[i].elements = elements;
		ctx[i].cuckoo_entries = cuckoo_entries;
		//ctx[i].inbitlen = bitlen;
	//	ctx[i].addr_bitlen = addr_bits;
		//ctx[i].outbitlen = outbitlen;
		//ctx[i].nbins = nbins;
		ctx[i].hs = &hs;
		ctx[i].startpos = i * ceil_divide(neles, ntasks);
		ctx[i].endpos = min(ctx[i].startpos + ceil_divide(neles, ntasks), neles);
		//cout << "Thread " << i << " starting from " << ctx[i].startpos << " going to " << ctx[i].endpos << " for " << neles << " elements" << endl;
		if(pthread_create(entry_gen_tasks+i, NULL, gen_cuckoo_entries, (void*) (ctx+i))) {
			cerr << "Error in creating new pthread at cuckoo hashing!" << endl;
			exit(0);
		}
	}

	//generate the cuckoo entries for all elements
	//for(i = 0; i < neles; i++) {
	//	gen_cuckoo_entry(elements + inbytelen * i, bitlen, addr_bits, cuckoo_entries + i, outbitlen, nbins, i);
	//}

	for(i = 0; i < ntasks; i++) {
		if(pthread_join(entry_gen_tasks[i], NULL)) {
			cerr << "Error in joining pthread at cuckoo hashing!" << endl;
			exit(0);
		}
	}

	//for(i = 0; i < nbins; i++) {
	//	cout << "Address " << i << " mapped to " << hs.address_used[i] << " times" << endl;
	//}
	//insert all elements into the cuckoo hash table
	for(i = 0; i < neles; i++) {
		if(!(insert_element(cuckoo_table, cuckoo_entries + i))) {
#ifdef COUNT_FAILS
			fails++;
			/*cout << "insertion failed for element " << (hex) << (*(((uint32_t*) elements)+i)) << ", inserting to address: ";
			for(uint32_t j = 0; j < NUM_HASH_FUNCTIONS; j++) {
				cout << (cuckoo_entries + i)->address[j] << ", ";
			}
			cout << (dec) << endl;*/
#else
			//cerr << "Insertion not successful for element " <<i <<"!" << endl;
			//exit(0);
#endif
		}
	}

#ifdef COUNT_FAILS
	if(fails > 0)
		cout << "insertion performed with " << fails << " fails" << endl;
#endif

	//Copy the final state of the cuckoo table into the hash table
	perm_ptr = perm;
	hash_table = (uint8_t*) calloc(nbins, hs.outbytelen);

	for(i = 0; i < nbins; i++) {
		if(cuckoo_table[i] != NULL) {
			memcpy(hash_table + i * hs.outbytelen, cuckoo_table[i]->val, hs.outbytelen);
			//cout << "copying value: " << (hex) << (unsigned int) cuckoo_table[i]->val[cuckoo_table[i]->pos][0] << (dec) << endl;
			*perm_ptr = cuckoo_table[i]->eleid;
			perm_ptr++;
			nelesinbin[i] = 1;
		} else {
			memset(hash_table + i * hs.outbytelen, DUMMY_ENTRY_CLIENT, hs.outbytelen);
			nelesinbin[i] = 0;
		}
	}

	//Cleanup
#ifndef TEST_UTILIZATION
	for(i = 0; i < neles; i++) {
		//for(j = 0; j < NUM_HASH_FUNCTIONS; j++) {
			free(cuckoo_entries[i].val);
		//}
	}
#endif
	free(cuckoo_entries);
	free(cuckoo_table);
	free(entry_gen_tasks);
	free(ctx);

	free_hashing_state(&hs);

	return hash_table;
}


void *gen_cuckoo_entries(void *ctx_void) {
	cuckoo_entry_gen_ctx* ctx  = (cuckoo_entry_gen_ctx*) ctx_void;
	hs_t* hs = ctx->hs;
	uint32_t i, inbytelen = ceil_divide(hs->inbitlen, 8);
	uint8_t* eleptr = ctx->elements + inbytelen * ctx->startpos;


	//generate the cuckoo entries for all elements
	for(i = ctx->startpos; i < ctx->endpos; i++, eleptr+=inbytelen) {
		gen_cuckoo_entry(eleptr, ctx->cuckoo_entries + i, hs, i);
	}
}


inline void gen_cuckoo_entry(uint8_t* in, cuckoo_entry_ctx* out, hs_t* hs, uint32_t ele_id) {
	uint32_t i;

	out->pos = 0;
	out->eleid = ele_id;

	//for(i = 0; i < NUM_HASH_FUNCTIONS; i++) {
#ifndef TEST_UTILIZATION
		out->val = (uint8_t*) malloc(hs->outbytelen);
#endif
		hashElement(in, out->address, out->val, hs);
	//}
}

inline bool insert_element(cuckoo_entry_ctx** ctable, cuckoo_entry_ctx* element) {
	cuckoo_entry_ctx *evicted, *tmp_evicted;
	uint32_t i, ev_pos, iter_cnt;
#ifdef DEBUG_CUCKOO
	cout << "iter_cnt = " << iter_cnt << " for element " << (hex) << (*((uint32_t*) element->element)) << (dec) << ", inserting to address: "
			<< element->address[element->pos] << " or " << element->address[element->pos^1] << endl;
#endif

	for(iter_cnt = 0, evicted = element; iter_cnt < MAX_ITERATIONS; iter_cnt++) {
		//TODO: assert(addr < MAX_TAB_ENTRIES)
		for(i = 0; i < NUM_HASH_FUNCTIONS; i++) {//, ele_pos=(ele_pos+1)%NUM_HASH_FUNCTIONS) {
			if(ctable[evicted->address[i]] == NULL) {
				ctable[evicted->address[i]] = evicted;
				evicted->pos = i;
				return true;
			}
		}

		//choose random bin to evict other element
		ev_pos = evicted->address[(evicted->pos^iter_cnt) % NUM_HASH_FUNCTIONS];

		tmp_evicted = ctable[ev_pos];
		ctable[ev_pos] = evicted;
		evicted = tmp_evicted;

		//change position - if the number of HF's is increased beyond 2 this should be replaced by a different strategy
		evicted->pos = (evicted->pos+1) % NUM_HASH_FUNCTIONS;
	}

	//the highest number of iterations has been reached
	return false;
}
