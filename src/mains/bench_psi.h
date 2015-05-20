/*
 * bench_psi.h
 *
 *  Created on: Nov 10, 2014
 *      Author: mzohner
 */

#ifndef BENCH_PSI_H_
#define BENCH_PSI_H_

#include "../pk-based/dh-psi.h"
#include "../ot-based/ot-psi.h"
#include "../thirdparty-based/shpsi.h"
#include "../naive-hashing/naive-psi.h"
#include <fstream>
#include <iostream>
#include <string>


using namespace std;

//#define PRINT_INPUT_ELEMENTS
//#define PRINT_INTERSECTION

enum PSI_PROT {NAIVE=0, TTP=1, DH_ECC=2, OT_PSI=3, PROT_LAST=4};
enum etype {T_NUM, T_STR, T_FLAG, T_DOUBLE};

typedef struct {
	void* val;
	etype type;
	char opt_name;
	string help_str;
	bool required;
	bool set;
} parsing_ctx;


int32_t benchroutine(int32_t argc, char** argv);
int32_t psi_demonstrator(int32_t argc, char** argv);

void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename);


uint32_t exchange_information(uint32_t myneles, uint32_t mybytelen, uint32_t mysecparam, uint32_t mynthreads,
		uint32_t myprotocol, CSocket& sock);

void print_bench_usage();
void print_demo_usage();

void print_usage(string progname, parsing_ctx* options, uint32_t nops);

int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings);
int32_t read_bench_options(int32_t* argcp, char*** argvp, role_type* role, uint32_t* nelements, uint32_t* bytelen,
		uint32_t* secparam, string* address, uint16_t* port, uint32_t* ntasks, uint32_t* protocol, uint32_t* nclients,
		double* epsilon, bool* cardinality, field_type* ftype, bool* detailed_timings);


int32_t parse_options(int32_t* argcp, char*** argvp, parsing_ctx* options, uint32_t nops);

#endif /* BENCH_PSI_H_ */
