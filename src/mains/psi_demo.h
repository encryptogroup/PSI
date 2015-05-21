/*
 * demonstrator.h
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */

#ifndef DEMONSTRATOR_H_
#define DEMONSTRATOR_H_

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

int32_t psi_demonstrator(int32_t argc, char** argv);

void read_elements(uint8_t*** elements, uint32_t** elebytelens, uint32_t* nelements, string filename);

int32_t read_psi_demo_options(int32_t* argcp, char*** argvp, role_type* role, psi_prot* protocol, string* filename, string* address,
		uint32_t* nelements, bool* detailed_timings);


#endif /* DEMONSTRATOR_H_ */
