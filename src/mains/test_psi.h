/*
 * test_psi.h
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */

#ifndef TEST_PSI_H_
#define TEST_PSI_H_

#define SILENT_TESTS

#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include "../pk-based/dh-psi.h"
#include "../ot-based/ot-psi.h"
#include "../server-aided/sapsi.h"
#include "../naive-hashing/naive-psi.h"
#include "../util/parse_options.h"
#include "../util/helpers.h"


uint32_t test_psi_prot(role_type role, CSocket* sock, uint32_t nelements,
		uint32_t elebytelen, crypto* crypt);
uint32_t plaintext_intersect(uint32_t myneles, uint32_t pneles, uint32_t bytelen, uint8_t* myelements,
		uint8_t* pelements, uint8_t** result);
uint32_t set_up_parameters(role_type role, uint32_t myneles, uint32_t* mybytelen,
	uint8_t** elements, uint8_t** pelements, CSocket& sock, crypto* crypt);
int32_t read_psi_test_options(int32_t* argcp, char*** argvp, role_type* role, uint32_t* nruns);
void plot_set(uint8_t* set, uint32_t neles, uint32_t elebytelen);

#endif /* TEST_PSI_H_ */
