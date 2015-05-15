/*
 * bench_psi.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: mzohner
 */

#include "bench_psi.h"


int32_t main(int32_t argc, char** argv) {
	psi_demonstrator(argc, argv);
	//benchroutine(argc, argv);
}



int32_t benchroutine(int32_t argc, char** argv) {
	uint32_t nelements=0, elebytelen=4, symsecbits=128,
			intersect_size, i, ntasks=1, runs=1, j, protocol, nclients=2, pnelements;
	uint8_t *elements, *intersection;
	string address = "127.0.0.1";
	uint16_t port=7766;
	timeval begin, end;
	vector<CSocket> sockfd(ntasks);
	field_type ftype = ECC_FIELD;
	role_type role = (role_type) 0;
	uint64_t bytes_sent=0, bytes_received=0, mbfac;
	double epsilon=1.2;
	bool cardinality=false;
	bool detailed_timings = false;

	mbfac=1024*1024;

	read_bench_options(&argc, &argv, &role, &nelements, &elebytelen, &symsecbits,
			&address, &port, &ntasks, &protocol, &nclients, &epsilon, &cardinality, &ftype,
			&detailed_timings);

	if(role == SERVER) {
		if(protocol == TTP) {
			ntasks = nclients;
			sockfd.resize(ntasks);
		}
		listen(address.c_str(), port, sockfd.data(), ntasks);
	} else {
		for(i = 0; i < ntasks; i++)
			connect(address.c_str(), port, sockfd[i]);
	}

	crypto crypto(symsecbits, (uint8_t*) const_seed);

	//exchange number of items, bit-length of items, symmetric security parameter and protocol to make sure the parameters are correct
	if(protocol != TTP) {
		pnelements = exchange_information(nelements, elebytelen, symsecbits, ntasks, protocol, sockfd[0]);
	}

	if(protocol != TTP || role != SERVER) {
		elements = (uint8_t*) calloc(nelements * elebytelen, sizeof(uint8_t));
		crypto.gen_rnd(elements, elebytelen * nelements);
	}


#ifdef PRINT_INPUT_ELEMENTS
	for(i = 0; i < nelements; i++) {
		cout << "Element " << i << ": " << (hex);
		for(j = 0; j < elebytelen; j++)
			cout << (uint32_t) elements[i*elebytelen + j];
		cout << (dec) << endl;
	}
#endif

#ifndef BATCH
	cout << "Benchmarking protocol " << protocol << " on " << runs << " runs" << endl;
#endif
	gettimeofday(&begin, NULL);
	for(i = 0; i < runs; i++) {
		switch(protocol) {
		case NAIVE:
			naivepsi(role, nelements, pnelements, elebytelen, elements, &intersection, &crypto, sockfd.data(), ntasks);
			break;
		case TTP:
			ttppsi(role, nelements, elebytelen, elements, &intersection, &crypto, sockfd.data(), nclients, cardinality); break;
		case DH_ECC:
			intersect_size = dhpsi(role, nelements, pnelements, elebytelen, elements, &intersection, &crypto, sockfd.data(),
					ntasks, cardinality, ftype);
			break;
		case OT_PSI:
			intersect_size = otpsi(role, nelements, pnelements, elebytelen*8, elements, &intersection, &crypto, sockfd.data(),
					ntasks, epsilon, detailed_timings);
			break;
		default:break;
		}
	}
	gettimeofday(&end, NULL);

	for(i = 0; i < sockfd.size(); i++) {
		bytes_sent += sockfd[i].get_bytes_sent();
		bytes_received += sockfd[i].get_bytes_received();
	}
#ifdef BATCH
	cout << getMillies(begin, end) << "\t" << ((double) bytes_sent + bytes_received)/mbfac << endl;


#else
	cout << "Required time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;
	cout << "Data sent:\t" <<	((double)bytes_sent)/mbfac << " MB" << endl;
	cout << "Data received:\t" << ((double)bytes_received)/mbfac << " MB" << endl;
#endif

#ifdef PRINT_INTERSECTION

	cout << "Found " << intersect_size << " intersecting elements" << endl;
		if(!cardinality) {
		for(i = 0; i < intersect_size; i++) {
			for(j = 0; j < elebytelen; j++) {
				cout << (hex) << (uint32_t) intersection[i * elebytelen + j] << (dec);
			}
			cout << endl;
		}
	}
#endif
	if(protocol != TTP || role != SERVER) {
		free(elements);
	}
	return 0;
}



int32_t psi_demonstrator(int32_t argc, char** argv) {
	uint32_t nelements=0, elebytelen=16, symsecbits=128, intersect_size, i, j, ntasks=1, protocol=3,
			pnelements, *elebytelens, *res_bytelens;
	bool detailed_timings=false;
	uint8_t **elements, **intersection;
	string address="127.0.0.1";
	uint16_t port=7766;
	timeval t_start, t_end;
	vector<CSocket> sockfd(ntasks);
	string filename;
	uint64_t bytes_sent=0, bytes_received=0, mbfac;
	role_type role = (role_type) 0;
	double epsilon=1.2;

	mbfac=1024*1024;

	read_psi_demo_options(&argc, &argv, &role, &filename, &address, &nelements, &detailed_timings);

	if(role == SERVER) {
		listen(address.c_str(), port, sockfd.data(), ntasks);
	} else {
		for(i = 0; i < ntasks; i++)
			connect(address.c_str(), port, sockfd[i]);
	}

	gettimeofday(&t_start, NULL);

	//read in files and get elements and byte-length from there

	read_elements(&elements, &elebytelens, &nelements, filename);
	if(detailed_timings) {
		gettimeofday(&t_end, NULL);
	}

	pnelements = exchange_information(nelements, elebytelen, symsecbits, ntasks, protocol, sockfd[0]);
	//cout << "Performing private set-intersection between " << nelements << " and " << pnelements << " element sets" << endl;

	if(detailed_timings) {
		cout << "Time for reading elements:\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end)/1000 << " s" << endl;
	}

	crypto crypto(symsecbits, (uint8_t*) const_seed);

#ifndef BATCH
	cout << "Benchmarking protocol " << protocol << " on " << runs << " runs" << endl;
#endif
	intersect_size = otpsi(role, nelements, pnelements, elebytelens, elements, &intersection, &res_bytelens,
			&crypto, sockfd.data(), ntasks, epsilon, detailed_timings);
	gettimeofday(&t_end, NULL);


#ifdef PRINT_INTERSECTION
	if(role == CLIENT) {
		//cout << "Computation finished. Found " << intersect_size << " intersecting elements:" << endl;
		if(!detailed_timings) {
			for(i = 0; i < intersect_size; i++) {
				//cout << "\t";
				for(j = 0; j < res_bytelens[i]; j++) {
					cout << intersection[i][j];
				}
				cout << endl;
			}
		}
	}
#endif

	for(i = 0; i < sockfd.size(); i++) {
		bytes_sent += sockfd[i].get_bytes_sent();
		bytes_received += sockfd[i].get_bytes_received();
	}

	//cout << "Required time:\t" << fixed << std::setprecision(1) << getMillies(t_start, t_end)/1000 << " s" << endl;
	//cout << "Data sent:\t" <<	((double)bytes_sent)/mbfac << " MB" << endl;
	//cout << "Data received:\t" << ((double)bytes_received)/mbfac << " MB" << endl;

	for(i = 0; i < nelements; i++)
		free(elements[i]);
	free(elements);
	free(elebytelens);
	return 1;
}


void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename) {
	uint32_t i, j;
	ifstream infile(filename.c_str());
	if(!infile.good()) {
		cerr << "Input file " << filename << " does not exist, program exiting!" << endl;
		exit(0);
	}
	string line;
	if(*nelements == 0) {
		while (std::getline(infile, line)) {
			++*nelements;
		}
	}
	*elements=(uint8_t**) malloc(sizeof(uint8_t*)*(*nelements));
	*elebytelens = (uint32_t*) malloc(sizeof(uint32_t) * (*nelements));

	infile.clear();
	infile.seekg(ios::beg);
	for(i = 0; i < *nelements; i++) {
		assert(std::getline(infile, line));
		(*elebytelens)[i] = line.length();
		(*elements)[i] = (uint8_t*) malloc((*elebytelens)[i]);
		memcpy((*elements)[i], (uint8_t*) line.c_str(), (*elebytelens)[i]);

#ifdef PRINT_INPUT_ELEMENTS
		cout << "Element " << i << ": ";
		for(j = 0; j < (*elebytelens)[i]; j++)
			cout << (*elements)[i][j];
		cout << endl;
#endif
	}
}



uint32_t exchange_information(uint32_t myneles, uint32_t mybytelen, uint32_t mysecparam, uint32_t mynthreads,
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


int32_t read_bench_options(int32_t* argcp, char*** argvp, role_type* role, uint32_t* nelements, uint32_t* bytelen,
		uint32_t* secparam, string* address, uint16_t* port, uint32_t* ntasks, uint32_t* protocol, uint32_t* nclients,
		double* epsilon, bool* cardinality, field_type* ftype, bool* detailed_timings) {

	uint32_t int_role=0, int_port=0;
	bool useffc=false;

	parsing_ctx options[] = {{(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
			{(void*) protocol, T_NUM, 'p', "PSI protocol (0: Naive, 1: TTP, 2: DH, 3: OT)", true, false},
			{(void*) nelements, T_NUM, 'n', "Num elements", true, false},
			{(void*) bytelen, T_NUM, 'b', "Byte length", true, false},
			{(void*) secparam, T_NUM, 's', "Symmetric Security Bits", false, false},
			{(void*) address, T_STR, 'a', "IP-address", false, false},
			{(void*) &int_port, T_NUM, 'o', "Port", false, false},
			{(void*) ntasks, T_NUM, 't', "Number of threads", false, false},
			{(void*) nclients, T_NUM, 'c', "Number of clients for TTP based protocol", false, false},
			{(void*) epsilon, T_DOUBLE, 'e', "Epsilon in Cuckoo hashing", false, false},
			{(void*) cardinality, T_FLAG, 'y', "Compute cardinality (only for DH and TTP PSI)", false, false},
			{(void*) &useffc, T_FLAG, 'f', "Use finite-field cryptography", false, false},
			{(void*) detailed_timings, T_FLAG, 'd', "Enable Detailed Timings", false, false}
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage("PSI-Implementations", options, sizeof(options)/sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (role_type) int_role;

	assert(*protocol < PROT_LAST);
	if(int_port != 0) {
		assert(int_port < 1<<(sizeof(uint16_t)*8));
		*port = (uint16_t) int_port;
	}

	if(useffc) {
		*ftype = P_FIELD;
	}
	//delete options;

	return 1;
}


int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings) {

	uint32_t int_role;
	//parsing_ctx *options = new parsing_ctx[5];//(parsing_ctx*) calloc(noptions, sizeof(parsing_ctx));

	parsing_ctx options[] = {{(void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false},
			{(void*) filename, T_STR, 'f', "Input file", true, false},
			{(void*) address, T_STR, 'a', "IP-address", false, false},
			{(void*) nelements, T_NUM, 'n', "Num elements", false, false},
			{(void*) detailed_timings, T_FLAG, 't', "Flag: Detailed timings", false, false}
	};

	if(!parse_options(argcp, argvp, options, sizeof(options)/sizeof(parsing_ctx))) {
		print_usage("PSI_demo", options, sizeof(options)/sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (role_type) int_role;

	//delete options;

	return 1;
}



int32_t parse_options(int32_t* argcp, char*** argvp, parsing_ctx* options, uint32_t nops) {
	uint32_t result = 0;
	bool skip;
	uint32_t i;
	if(*argcp < 2)
		return -1;

	while((*argcp) > 1)
	{
		if ((*argvp)[1][0] != '-' || (*argvp)[1][1] == '\0' || (*argvp)[1][2] != '\0')
			return result;
		for(i = 0, skip=false; i < nops && !skip; i++) {
			if(	((*argvp)[1][1]) == options[i].opt_name) {
				switch(options[i].type) {
				case T_NUM:
					if (isdigit((*argvp)[2][0]))	{
						++*argvp;
						--*argcp;
						*((uint32_t*) options[i].val) = atoi((*argvp)[1]);
					}
					break;
				case T_DOUBLE:
					++*argvp;
					--*argcp;
					*((double*) options[i].val) = atof((*argvp)[1]);
					break;
				case T_STR:
					++*argvp;
					--*argcp;
					*((string*) options[i].val) = (*argvp)[1];
					break;
				case T_FLAG:
					*((bool*)options[i].val) = true;
					break;
				}
				++result;
				++*argvp;
				--*argcp;
				options[i].set=true;
				skip = true;
			}
		}
	}

	for(i = 0; i < nops; i++) {
		if(options[i].required && !options[i].set)
			return 0;
	}
	return 1;
}


void print_usage(string progname, parsing_ctx* options, uint32_t nops) {
	uint32_t i;
	cout << "Usage: ./"<<progname;
	for(i = 0; i < nops; i++) {
		cout << " -" << options[i].opt_name << " [" << options[i].help_str <<"]";
	}
	cout << endl << "Program exiting" << endl;
}


void print_bench_usage() {
	cout << "Usage: ./PSI_demo.exe -r [0 (server)/1 (client)] -f [input file] -n [num_elements (optional, default: all elements in file)]"
			<< " -a [ip_address (optional, default:localhost)] -t [enable detailed timings and no output printing (optional, default: off)]" << endl;
	cout << "Program exiting" << endl;
	exit(0);
}


void print_demo_usage() {
	cout << "Usage: ./PSI_demo.exe -r [0 (server)/1 (client)] -f [input file] -n [num_elements (optional, default: all elements in file)]"
			<< " -a [ip_address (optional, default:localhost)] -t [enable detailed timings and no output printing (optional, default: off)]" << endl;
	cout << "Program exiting" << endl;
	exit(0);
}
