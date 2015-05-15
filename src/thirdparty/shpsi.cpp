#include "shpsi.h"



/*int32_t main(int32_t argc, char** argv) {
	uint32_t pid, nclients, nelements, elebytelen, symsecbits;
	uint8_t *elements, *intersection;
	const char* address;
	uint16_t port;
	timeval begin, end;

	if(argc < 2) {
		print_sh_psi_usage();
	} else {
		pid = atoi(argv[1]);
		if((pid == 0 && argc < 5) || (pid > 0 && argc < 6)) print_sh_psi_usage();
	}

	if(pid == 0) { 	// Play as server
		nclients = atoi(argv[2]);
		address = argv[3];
		port = (uint16_t) atoi(argv[4]);
		server_routine(nclients, address, port);
	} else { // Play as client
		nelements = atoi(argv[2]);
		elebytelen = atoi(argv[3]);
		symsecbits = atoi(argv[4]);
		address = argv[5];
		port = atoi(argv[6]);
		elements = (uint8_t*) malloc(sizeof(uint8_t) * elebytelen * nelements);
		crypto crypto(symsecbits);
		crypto.gen_rnd(elements, elebytelen * nelements);

#ifdef DEBUG
		//Load some dummy-values
		for(uint32_t i = 0; i < nelements; i++) {
			((uint32_t*) elements)[i] = i+(nelements/pid);
		}
#endif
	    gettimeofday(&begin, NULL);
		client_routine(nelements, elebytelen, elements, &intersection, symsecbits, address, port);
	    gettimeofday(&end, NULL);
	    cout << "Computing the intersection took " << getMillies(begin, end) << " ms" << endl;
	}
	cout << "Program execution finished" << endl;
	return 0;
}*/

void server_routine(uint32_t nclients, CSocket* socket, bool cardinality) {
	//cout << "Starting server for " << nclients << " clients on address " << address << ":" << port << endl;

	CSocket* sockfds = socket;//(CSocket*) malloc(sizeof(CSocket) * nclients);
	uint32_t* neles = (uint32_t*) malloc(sizeof(uint32_t) * nclients);
	uint8_t** csets = (uint8_t**) malloc(sizeof(uint8_t*) * nclients);
	uint8_t* intersect;
	uint32_t temp, maskbytelen, intersectsize, minset, i;

#ifndef BATCH
	cout << "Connections with all " << nclients << " clients established" << endl;
#endif

	/* Receive the input sizes and bit lengths for all clients */
	for(i = 0; i < nclients; i++) {
		sockfds[i].Receive(neles+i, sizeof(uint32_t));
		sockfds[i].Receive(&temp, sizeof(uint32_t));
		if(i == 0) { maskbytelen = temp; minset = neles[i];}
		if(neles[i] < minset) minset = neles[i];
		assert(maskbytelen == temp);
#ifndef BATCH
		cout << "Client " << i << " holds " << neles[i] << " elements of length " << (temp * 8) << "-bit" << endl;
#endif
	}
#ifndef BATCH
	cout <<"Receiving the client's elements" << endl;
#endif
	/* Allocate sufficient size for the intersecting elements */
	intersect = (uint8_t*) malloc(sizeof(uint8_t*) * minset * maskbytelen);

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
	intersectsize = compute_intersection(nclients, neles, csets, intersect, maskbytelen);
#ifndef BATCH
	cout << "sending all " << intersectsize << " intersecting elements to the clients" << endl;
#endif
	/* Send the intersection size and intersecting elements to all clients */
	for(i = 0; i < nclients; i++) {
		sockfds[i].Send(&intersectsize, sizeof(uint32_t));
		if(!cardinality)
			sockfds[i].Send(intersect, intersectsize * maskbytelen);
	}

	/* Cleanup */
	free(neles);
}

/*
 * compute the intersection using a hash table - is optimized for the two-party case,
 * for the n-party case a BF-based approach makes more sense.
 */
//TODO currently only works for 128 bit masks
uint32_t compute_intersection(uint32_t nclients, uint32_t* neles, uint8_t** csets, uint8_t* intersect, uint32_t entrybytelen) {
    // Create the GHashTable
    GHashTable *map = NULL, *tmpmap = NULL;
    GHashTableIter iter;
	timeval begin, end;

    map = g_hash_table_new_full(
    		g_int64_hash, g_int64_equal,
		    NULL, // no cleanup for key
		    NULL // cleanup value
		    );

    uint32_t i, j, intersectsize, ctr = 0;
    uint64_t* tmpval = (uint64_t*) malloc(sizeof(uint64_t));
    uint64_t* tmpkey = (uint64_t*) malloc(sizeof(uint64_t));
#ifndef BATCH
    cout << "Inserting the items into the hash table " << endl;
#endif
    gettimeofday(&begin, NULL);
    for(i=0;i<neles[0];i++) {
#ifdef DEBUG
    	cout << "Inserted item: " << (hex) << ((uint64_t*) csets[0])[2*i] << " "<< ((uint64_t*) csets[0])[2*i+1] << (dec) << endl;
#endif
	    g_hash_table_insert(map,(void*) &((uint64_t*)csets[0])[2*i], &(((uint64_t*)csets[0])[2*i+1]));
    }
#ifdef DEBUG
    g_hash_table_foreach( map, printKeyValue, NULL );
#endif
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
    				NULL, (void**) &tmpval) && (*tmpval == ((uint64_t*)csets[i])[2*j+1])) {
#ifdef DEBUG
    			cout << "Key was found" << endl;
#endif
    			g_hash_table_insert(tmpmap,(void*) &(((uint64_t*)csets[i])[2*j]),&(((uint64_t*)csets[i])[2*j+1]));

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
    	((uint64_t*) intersect)[ctr++] = tmpkey[0];
    	((uint64_t*) intersect)[ctr++] = tmpval[0];
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


uint32_t client_routine(uint32_t neles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt, CSocket* socket, bool cardinality) {
	uint32_t maskbytelen = 16, intersectsize, i, j;
	uint8_t* masks = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	uint8_t* intersect = (uint8_t*) malloc(sizeof(uint8_t) * neles * maskbytelen);
	uint32_t* perm;
	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);

	uint32_t* tmpval = (uint32_t*) malloc(sizeof(uint32_t));
	GHashTable *map;

	//crypto crypto(symsecbits, (uint8_t*) const_seed);

//	cout << "Starting client with " << neles << " elements of " << (8*elebytelen) << "-bit length with server "
//			<< address << ":" << port << endl;

	CSocket* sockfd = socket;
	//connect(address, port, sockfd);
	sockfd->Send((uint8_t*) &neles, sizeof(uint32_t));
	sockfd->Send((uint8_t*) &maskbytelen, sizeof(uint32_t));


	perm = mask_and_permute_elements(neles, elebytelen, elements, maskbytelen, masks, crypt->get_seclvl().symbits, crypt);

	sockfd->Send(masks, maskbytelen * neles);

	if(!cardinality) {
		for(i = 0; i < neles; i++) {
			invperm[perm[i]] = i;
		}

		map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
		for(i = 0; i < neles; i++) {
			g_hash_table_insert(map,(void*) &((uint64_t*)masks)[2*i], &(invperm[i]));
		}
	}


	sockfd->Receive(&intersectsize, sizeof(uint32_t));
	if(!cardinality) {
		sockfd->Receive(intersect, maskbytelen * intersectsize);

#ifdef DEBUG
		cout << "The intersection contains " << intersectsize << " elements: " << endl;
		for(i = 0; i < intersectsize; i++) {
			cout << (hex) << ((uint64_t*)intersect)[2*i] << " " << ((uint64_t*)intersect)[2*i+1] << (dec) << endl;
		}
#endif

		*result = (uint8_t*) malloc(elebytelen * intersectsize);
		//uint8_t* tmpbuf = (uint8_t*) malloc(maskbytelen);
		for(i = 0; i < intersectsize; i++) {
			g_hash_table_lookup_extended(map, (void*) &(((uint64_t*)intersect)[2*i]), NULL, (void**) &tmpval);
			memcpy((*result) + i * elebytelen, elements + tmpval[0] * elebytelen, elebytelen);
			//crypto.decrypt(tmpbuf, intersect+i*maskbytelen, maskbytelen);
			//memcpy((*result) + i * elebytelen, tmpbuf, elebytelen);
#ifdef DEBUG
			cout << ((uint32_t*) elements)[tmpval[0]] << ", ";
#endif
		}
#ifdef DEBUG
	cout << endl;
#endif
	}

	free(perm);
	free(invperm);

	return intersectsize;
}


void printKeyValue( gpointer key, gpointer value, gpointer userData ) {
	uint64_t realKey = *((uint64_t*)key);
	uint64_t realValue = *((uint64_t*)value);

	cout << (hex) << realKey << ": "  << realValue << (dec) << endl;
	return;
}

uint32_t* mask_and_permute_elements(uint32_t neles, uint32_t elebytelen, uint8_t*
		elements, uint32_t maskbytelen, uint8_t* masks, uint32_t symsecbits, crypto* crypto) {
	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint8_t* maskpermptr;
	uint32_t i;

	//Get random permutation
	crypto->gen_rnd_perm(perm, neles);
	//crypto->seed_aes_enc(client_psk);

	//Hash and permute all elements
	for(i = 0; i < neles; i++) {
		//cout << "Performing encryption for " << i << "-th element " << ((uint32_t*) elements)[i] << ": ";
		maskpermptr = masks + perm[i] * maskbytelen;
		crypto->hash(maskpermptr, maskbytelen, elements + i * elebytelen, elebytelen);
		//crypto->encrypt(maskpermptr, elements+i*elebytelen, elebytelen);
		//cout <<(hex)<< ((uint64_t*) maskpermptr)[0] << ((uint64_t*) maskpermptr)[1] << (dec) << endl;
#ifdef DEBUG
		cout << "Resulting hash for element " << ((uint32_t*)elements)[i] << ": " << (hex) << ((uint64_t*) maskpermptr)[0] <<
				" " << ((uint64_t*) maskpermptr)[1] << (dec) <<  endl;
#endif
	}


	//free(perm);
	return perm;
}

uint32_t ttppsi(role_type role, uint32_t neles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** intersection, crypto* crypt, CSocket* sockets, uint32_t nclients, bool cardinality) {

	if(role == 0) { //Start the server
		//TODO maybe rerun infinitely
		server_routine(nclients, sockets, cardinality);
		return 0;
	} else { //Start clients
		return client_routine(neles, elebytelen, elements, intersection, crypt, sockets, cardinality);
	}
}
