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
#include "../server-aided/sapsi.h"
#include "../naive-hashing/naive-psi.h"
#include <fstream>
#include <iostream>
#include <string>
#include "../util/parse_options.h"
#include "../util/helpers.h"


using namespace std;

//#define PRINT_INPUT_ELEMENTS
//#define PRINT_INTERSECTION



int32_t benchroutine(int32_t argc, char** argv);

void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename);

int32_t read_bench_options(int32_t* argcp, char*** argvp, role_type* role, uint32_t* nelements, uint32_t* bytelen,
		uint32_t* secparam, string* address, uint16_t* port, uint32_t* ntasks, psi_prot* protocol, uint32_t* nclients,
		double* epsilon, bool* cardinality, field_type* ftype, bool* detailed_timings);


#endif /* BENCH_PSI_H_ */
