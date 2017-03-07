#include "sapsi.h"

void server_routine(uint32_t nclients, CSocket* socket, bool cardinality) {
	//cout << "Starting server for " << nclients << " clients on address " << address << ":" << port << endl;

	CSocket* sockfds = socket;//(CSocket*) malloc(sizeof(CSocket) * nclients);
	uint32_t* neles = (uint32_t*) malloc(sizeof(uint32_t) * nclients);
	uint8_t** csets = (uint8_t**) malloc(sizeof(uint8_t*) * nclients);
	uint32_t temp, maskbytelen, intersectsize, minset, i, j;
	CBitVector* intersection = new CBitVector[nclients];

#ifndef BATCH
	cout << "Connections with all " << nclients << " clients established" << endl;
#endif

	/* Receive the input sizes and bit lengths for all clients */
	for(i = 0; i < nclients; i++) {
		sockfds[i].Receive(neles+i, sizeof(uint32_t));
		sockfds[i].Receive(&temp, sizeof(uint32_t));
		if(i == 0) { maskbytelen = temp; minset = neles[i];}
		if(neles[i] < minset) minset = neles[i];
#ifndef BATCH
		cout << "Client " << i << " holds " << neles[i] << " elements of length " << (temp * 8) << "-bit" << endl;
#endif
		intersection[i].ResizeinBytes(ceil_divide(neles[i], 8));
		intersection[i].Reset();
		assert(maskbytelen == temp);

	}
#ifndef BATCH
	cout <<"Receiving the client's elements" << endl;
#endif

	/* Receive the permuted and masked sets of all clients */
	for(i = 0; i < nclients; i++) {
		temp = sizeof(uint8_t) * neles[i] * maskbytelen;
		csets[i] = (uint8_t*) malloc(temp);
		sockfds[i].Receive(csets[i], temp);
	}
#ifndef BATCH
	cout << "Computing intersection for the clients" << endl;
#endif
	/* Compute Intersection */
	intersectsize = compute_intersection(nclients, neles, csets, intersection, maskbytelen);


	/* Enter at which position an intersection was found */
#ifndef BATCH
	cout << "sending all " << intersectsize << " intersecting elements to the clients" << endl;
#endif
	/* Send the intersection size and intersecting elements to all clients */
	for(i = 0; i < nclients; i++) {
		sockfds[i].Send(&intersectsize, sizeof(uint32_t));
		if(!cardinality)
			sockfds[i].Send(intersection[i].GetArr(), ceil_divide(neles[i], 8));
	}

	/* Cleanup */
	free(neles);
}

/*
 * compute the intersection using a hash table - is optimized for the two-party case,
 * for the n-party case a BF-based approach makes more sense.
 */
//TODO currently only works for 128 bit masks
uint32_t compute_intersection(uint32_t nclients, uint32_t* neles, uint8_t** csets, CBitVector* intersection, uint32_t entrybytelen) {
    // Create the GHashTable
    GHashTable *map = NULL, *tmpmap = NULL;
    GHashTableIter iter;
	timeval begin, end;

    map = g_hash_table_new_full(
    		g_int64_hash, g_int64_equal,
		    NULL, // no cleanup for key
		    NULL // cleanup value
		    );

    uint32_t i, j, intersectsize, ctr = 0, k;
    uint64_t* tmpval;
    uint64_t* tmpkey = (uint64_t*) malloc(sizeof(uint64_t));
    uint64_t* query;
#ifndef BATCH
    cout << "Inserting the items into the hash table " << endl;
#endif
    gettimeofday(&begin, NULL);
    for(i=0;i<neles[0];i++) {
#ifdef DEBUG
    	cout << "Inserted item: " << (hex) << ((uint64_t*) csets[0])[2*i] << " "<< ((uint64_t*) csets[0])[2*i+1] << (dec) << endl;
#endif
    	tmpval = (uint64_t*) malloc(2*sizeof(uint64_t));
    	tmpval[0] = (((uint64_t*)csets[0])[2*i+1]);
    	tmpval[1] = i;
	    g_hash_table_insert(map,(void*) &((uint64_t*)csets[0])[2*i], tmpval);//&(((uint64_t*)csets[0])[2*i+1]));
    }
    gettimeofday(&end, NULL);
#ifdef TIMING
    cout << "Insertion took " << getMillies(begin, end) << " ms" << endl;
#endif
    gettimeofday(&begin, NULL);

#ifdef DEBUG
    cout << "Checking for duplicates " << endl;
#endif
    for(i = 1; i < nclients; i++) {
    	tmpmap = g_hash_table_new_full(
    			g_int64_hash, g_int64_equal,
    		    NULL, // no cleanup for key
    		    NULL // cleanup value
    		    );
    	for(j = 0; j < neles[i]; j++) {
#ifdef DEBUG
    		cout << "Checking for Key: " << (hex) << ((uint64_t*) csets[i])[2*j] << " "<< ((uint64_t*) csets[i])[2*j+1] << (dec) << endl;
#endif
    		if(g_hash_table_lookup_extended(map, (void*) &(((uint64_t*)csets[i])[2*j]),
    				NULL, (void**) &query) && (*query == ((uint64_t*)csets[i])[2*j+1])) {
#ifdef DEBUG
    			cout << "Key was found" << endl;
#endif
    	    	tmpval = (uint64_t*) malloc((i+2)*sizeof(uint64_t));
    	    	tmpval[0] = (((uint64_t*)csets[i])[2*j+1]);
    	    	for(k = 1; k < i+1; k++) {
    	    		tmpval[k] = query[k];
    	    	}
    	    	tmpval[i+1] = j;
    			g_hash_table_insert(tmpmap,(void*) &(((uint64_t*)csets[i])[2*j]), tmpval);//&(((uint64_t*)csets[i])[2*j+1]));

    		} else {
#ifdef DEBUG
    			cout << "Key not found" << endl;
#endif
    		}
    	}
    	//Delete map
    	g_hash_table_destroy(map);
    	map = tmpmap;
    }
    gettimeofday(&end, NULL);
#ifdef TIMING
    cout << "Checking took " << getMillies(begin, end) << " ms" << endl;
#endif
    gettimeofday(&begin, NULL);

    intersectsize = g_hash_table_size(map);

    //intersect = (uint8_t*) malloc(sizeof(uint8_t) * intersectsize * entrybytelen);

#ifdef DEBUG
    cout << "Intersection contains the elements: " << endl;
#endif
    g_hash_table_iter_init (&iter, map);
    //Iterate over all key / element pairs and store them in the intersection
    while(g_hash_table_iter_next (&iter, (void**) &tmpkey, (void**) &tmpval)) {
#ifdef DEBUG
    	cout << (hex) << tmpkey[0] << " " << tmpval[0] << (dec)<< endl;
#endif
    	for(i = 0; i < nclients; i++) {
    		intersection[i].SetBit(tmpval[i+1], 1);
    	}
    }
    gettimeofday(&end, NULL);
#ifdef TIMING
    cout << "Iterating took " << getMillies(begin, end) << " ms" << endl;
#endif

    g_hash_table_destroy(map);

    //free(tmpval);
    //free(tmpkey);
#ifdef DEBUG
    cout << "returning" << endl;
#endif
	return intersectsize;
}


uint32_t client_routine(uint32_t neles, task_ctx ectx, uint32_t* matches,
		crypto* crypt_env, CSocket* socket, uint32_t ntasks, bool cardinality) {
	uint32_t maskbytelen, intersectsize, i, matchctr;


	uint8_t* masks;
	uint32_t *perm, *invperm;
	CBitVector inIntersection(neles);

	//TODO works only fine for equally sized sets, if one set is bigger than the other, this will fail!
	maskbytelen = 16;//ceil_divide(crypt_env->get_seclvl().statbits + 2*ceil_log2(neles), 8);

	masks = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	perm  = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);

	/* Generate the random permutation the elements */
	crypt_env->gen_rnd_perm(perm, neles);

	socket->Send((uint8_t*) &neles, sizeof(uint32_t));
	socket->Send((uint8_t*) &maskbytelen, sizeof(uint32_t));

	ectx.eles.outbytelen = maskbytelen,
	ectx.eles.nelements = neles;
	ectx.eles.output = masks;
	ectx.eles.perm = perm;
	ectx.sctx.symcrypt = crypt_env;
	ectx.sctx.keydata = (uint8_t*) const_seed;

	run_task(ntasks, ectx, psi_hashing_function);

	socket->Send(masks, maskbytelen * neles);

	socket->Receive(&intersectsize, sizeof(uint32_t));

	for(i = 0; i < neles; i++) {
		invperm[perm[i]] = i;
	}

	if(!cardinality) {
		socket->Receive(inIntersection.GetArr(), ceil_divide(neles, 8));

		for(i = 0, matchctr = 0; i < neles; i++) {
			if(inIntersection.GetBit(i)) {
				matches[matchctr] = invperm[i];
				matchctr++;
			}
		}
	}

	free(perm);
	free(invperm);

	return intersectsize;
}

uint32_t ttppsi(role_type role, uint32_t neles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt, CSocket* sockets, uint32_t ntasks, uint32_t nclients, bool cardinality) {

	if(role == 0) { //Start the server
		//TODO maybe rerun infinitely
		server_routine(nclients, sockets, cardinality);
		return 0;
	} else { //Start clients
		task_ctx ectx;
		ectx.eles.input1d = elements;
		ectx.eles.fixedbytelen = elebytelen;
		ectx.eles.hasvarbytelen = false;

		uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * neles);
		uint32_t intersect_size = client_routine(neles, ectx, matches, crypt, sockets, ntasks, cardinality);

		create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

		free(matches);

		return intersect_size;
	}
}


uint32_t ttppsi(role_type role, uint32_t neles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt, CSocket* sockets,
		uint32_t ntasks, uint32_t nclients, bool cardinality) {

	if(role == 0) { //Start the server
		//TODO maybe rerun infinitely
		server_routine(nclients, sockets, cardinality);
		return 0;
	} else { //Start clients
		task_ctx ectx;
		ectx.eles.input2d = elements;
		ectx.eles.varbytelens = elebytelens;
		ectx.eles.hasvarbytelen = true;

		uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * neles);
		uint32_t intersect_size = client_routine(neles, ectx, matches, crypt, sockets, ntasks, cardinality);

		create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);

		free(matches);

		return intersect_size;
	}
}
