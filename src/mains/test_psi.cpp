/*
 * test_psi.cpp
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */

#include "test_psi.h"

int32_t main(int32_t argc, char** argv) {
	string address="127.0.0.1";
	uint32_t nelements, elebytelen, ntasks=1, nruns=1, symsecbits=128;
	uint64_t rnd;
	role_type role = (role_type) 0;
	vector<CSocket> sockfd(ntasks);
	uint16_t port=7766;
	uint8_t* seed = (uint8_t*) malloc(AES_BYTES);


	read_psi_test_options(&argc, &argv, &role, &nruns);

	memcpy(seed, const_seed, AES_BYTES);
	seed[0] = role;
	crypto* crypt = new crypto(symsecbits, seed);

	crypt->gen_rnd((uint8_t*) &rnd, sizeof(uint64_t));
	srand((unsigned)rnd+time(0));

	if(role == SERVER) {
		listen(address.c_str(), port, sockfd.data(), ntasks);
	} else {
		for(uint32_t i = 0; i < ntasks; i++)
			connect(address.c_str(), port, sockfd[i]);
	}

	for(uint32_t i = 0; i < nruns; i++) {
		if(role == CLIENT) cout << "Running test on iteration " << i << std::flush;
		nelements = rand() % (1<<12);
		elebytelen = (rand() % 12) + 4;

		test_psi_prot(role, sockfd.data(), nelements, elebytelen, crypt);
		if(role == CLIENT) cout << endl;
	}

	if(role == CLIENT) cout << "All tests successfully passed" << endl;
}


uint32_t test_psi_prot(role_type role, CSocket* sock, uint32_t nelements,
		uint32_t elebytelen, crypto* crypt) {
	double epsilon=1.2;
	uint32_t p_inter_size, n_inter_size, ot_inter_size, dh_inter_size, i, j, ntasks=1,
			pnelements, nclients = 2;
	uint8_t *elements, *pelements, *p_intersection, *n_intersection, *ot_intersection, *dh_intersection;

	//if(protocol != TTP)

	pnelements = set_up_parameters(role, nelements, &elebytelen, &elements, &pelements, sock[0], crypt);

	if(role == CLIENT) cout << " for |A|=" << nelements << ", |B|=" << pnelements << ", b=" << elebytelen << ": " << std::flush;


	p_inter_size = plaintext_intersect(nelements, pnelements, elebytelen, elements, pelements,
			&p_intersection);
	//cout << "Plaintext intersection computed " << endl;
	if(role == CLIENT) cout << "." << std::flush;

	n_inter_size = naivepsi(role, nelements, pnelements, elebytelen, elements, &n_intersection,	crypt,
			sock, ntasks);
	//cout << "Naive intersection computed " << endl;
	if(role == CLIENT) cout << "." << std::flush;

	dh_inter_size = dhpsi(role, nelements, pnelements, elebytelen, elements, &dh_intersection, crypt,
			sock, ntasks);
	//cout << "DH intersection computed " << endl;
	if(role == CLIENT) cout << "." << std::flush;

	ot_inter_size = otpsi(role, nelements, pnelements, elebytelen, elements, &ot_intersection,
			crypt, sock, ntasks, epsilon);
	//cout << "OT intersection computed " << endl;
	if(role == CLIENT) cout << "." << std::flush;


	if(role == CLIENT) {
		bool success = true;
		success &= (p_inter_size == n_inter_size);
		success &= (p_inter_size == dh_inter_size);
		success &= (p_inter_size == ot_inter_size);

		for(uint32_t i = 0; i < p_inter_size * elebytelen; i++) {
			success &= (p_intersection[i] == n_intersection[i]);
			success &= (p_intersection[i] == dh_intersection[i]);
			success &= (p_intersection[i] == ot_intersection[i]);
		}

		if(!success) {
			cout << "Error in tests for " << nelements << " and " << pnelements << " on " << elebytelen
					<< " byte length: " << endl;

			cout << "\t" << p_inter_size << " elements in verification intersection" << endl;
			cout << "\t" << n_inter_size << " elements in naive intersection" << endl;
			cout << "\t" << dh_inter_size << " elements in DH intersection" << endl;
			cout << "\t" << ot_inter_size << " elements in OT intersection" << endl;

			cout << "Plaintext intersection (" << p_inter_size << "): " << endl;
			//plot_set(p_intersection, p_inter_size, elebytelen);
			cout << "Naive intersection (" << n_inter_size << "): " << endl;
			//plot_set(n_intersection, n_inter_size, elebytelen);
			cout << "DH intersection (" << dh_inter_size << "): "  << endl;
			//plot_set(dh_intersection, dh_inter_size, elebytelen);
			cout << "OT intersection: (" << ot_inter_size << "): " << endl;
			//plot_set(ot_intersection, ot_inter_size, elebytelen);
		}

		if(p_inter_size > 0)
			free(p_intersection);
		if(n_inter_size > 0)
			free(n_intersection);
		if(dh_inter_size > 0)
			free(dh_intersection);
		if(ot_inter_size > 0)
			free(ot_intersection);

		assert(success);
	}

	free(elements);
	free(pelements);


	return 1;
}

void plot_set(uint8_t* set, uint32_t neles, uint32_t elebytelen) {
	for(uint32_t i = 0; i < neles; i++) {
		cout << i << ": ";
		for(uint32_t j = 0; j < elebytelen; j++) {
			cout << setw(2) << setfill('0') << (hex) << (uint32_t) set[i*elebytelen+j];
		}
		cout << (dec) << endl;
	}
}


uint32_t plaintext_intersect(uint32_t myneles, uint32_t pneles, uint32_t bytelen, uint8_t* myelements,
		uint8_t* pelements, uint8_t** result) {
	uint32_t intersect_size = 0, i, j;
	uint64_t tmpkey = 0;
	uint8_t *tmpval;
	uint8_t** matches = (uint8_t**) malloc(sizeof(uint8_t*) * min(myneles, pneles));
	uint32_t keylen = min((uint32_t) bytelen, (uint32_t) 8);
	bool success;


	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < myneles; i++) {
		memcpy(&tmpkey, myelements+i*bytelen, keylen);
		g_hash_table_insert(map,(void*) &tmpkey, myelements+i*bytelen);
	}

	for(i = 0; i < pneles; i++) {
		memcpy(&tmpkey, pelements+i*bytelen, keylen);
		if(g_hash_table_lookup_extended(map, (void*) &tmpkey, NULL, (void**) &tmpval)) {
			success = true;
			if(bytelen > 8) {
				for(j = 8; j < bytelen && success; j++) {
					if(tmpval[j] != pelements[i*bytelen+j])
						success = false;
				}
			}
			if(success) {
				matches[intersect_size] = (uint8_t*) tmpval;
				intersect_size++;
			}

			assert(intersect_size <= min(myneles, pneles));
		}
	}

	*result = (uint8_t*) malloc(intersect_size * bytelen);

	for(i = 0; i < intersect_size; i++) {
		memcpy((*result) + i * bytelen, matches[i], bytelen);
	}

	free(matches);
	return intersect_size;
}


uint32_t set_up_parameters(role_type role, uint32_t myneles, uint32_t* mybytelen,
	uint8_t** elements, uint8_t** pelements, CSocket& sock, crypto* crypt) {

	uint32_t pneles, nintersections, offset;

	//Exchange meta-information and equalize byte-length
	sock.Send(&myneles, sizeof(uint32_t));
	sock.Receive(&pneles, sizeof(uint32_t));

	if(role == SERVER) {
		sock.Send(mybytelen, sizeof(uint32_t));
	} else {
		sock.Receive(mybytelen, sizeof(uint32_t));
	}
	*elements = (uint8_t*) malloc(myneles * *mybytelen);
	*pelements = (uint8_t*) malloc(pneles * *mybytelen);

	crypt->gen_rnd(*elements, myneles * *mybytelen);

	//Exchange elements for later check
	if(role == SERVER) {
		sock.Send(*elements, myneles * *mybytelen);
		sock.Receive(*pelements, pneles * *mybytelen);
	} else { //have the client use some of the servers values s.t. the intersection is not disjoint
		sock.Receive(*pelements, pneles * *mybytelen);
		nintersections = rand() % min(myneles, pneles);
		offset = myneles / nintersections;

		for(uint32_t i = 0; i < nintersections; i++) {
			memcpy(*elements + i * offset * *mybytelen, *pelements + i * *mybytelen, *mybytelen);
		}
		sock.Send(*elements, myneles * *mybytelen);
	}

	return pneles;
}


int32_t read_psi_test_options(int32_t* argcp, char*** argvp, role_type* role, uint32_t* nruns) {
	uint32_t int_role;
	parsing_ctx options[] = {{(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
			{(void*) nruns, T_NUM, 't', "#of test iterations", false, false},
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage(argvp[0][0], options, sizeof(options)/sizeof(parsing_ctx));
		exit(0);
	}

	assert(int_role < 2);
	*role = (role_type) int_role;

	return 1;
}
