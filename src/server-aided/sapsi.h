/*
 * sapsi.h
 *
 *  Created on: Jul 1, 2014
 *      Author: mzohner
 */

#ifndef SHPSI_H_
#define SHPSI_H_

#include <glib.h>
#include "../util/crypto/crypto.h"
#include "../util/socket.h"
#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/helpers.h"
#include "../util/cbitvector.h"



/* start both roles*/
uint32_t ttppsi(role_type role, uint32_t neles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** intersection, crypto* crypt, CSocket* socket, uint32_t ntasks, uint32_t nclients = 2, bool cardinality=false);

uint32_t ttppsi(role_type role, uint32_t neles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt, CSocket* sockets,
		uint32_t ntasks, uint32_t nclients = 2, bool cardinality = false);

/*
 * Params:
 * neles: number of elements in the clients' set
 * elebytelen: bytelength of the elements
 * elements: byte pointer to the client's set
 * intersection: a byte array that holds the intersection upon returning
 * address: address of the server
 * port: port that the server is listening on
 * return: number of intersecting elements
 */
uint32_t client_routine(uint32_t neles, task_ctx ectx, uint32_t* matches, crypto* crypt,
		CSocket* socket, uint32_t ntasks, bool cardinality);

/*
 * Mask and permute the elements using the pre-shared key
 */
uint32_t* mask_and_permute_elements(uint32_t neles, uint32_t elebytelen, uint8_t*
		elements, uint32_t maskbytelen, uint8_t* masks, uint32_t symsecbits, crypto* crypto);


/*
 * Params:
 * nclients: number of participating clients
 * address: address of the server
 * port: port that the server is listening on
 */
void server_routine(uint32_t nclients, CSocket* socket, bool cardinality);

uint32_t compute_intersection(uint32_t nclients, uint32_t* neles, uint8_t** csets, CBitVector* intersection, uint32_t entrybytelen);

void printKeyValue( gpointer key, gpointer value, gpointer userData );

#endif /* SHPSI_H_ */
