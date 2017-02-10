/*
 * ot-psi.h
 *
 *  Created on: Jul 16, 2014
 *      Author: mzohner
 */

#ifndef OT_PSI_H_
#define OT_PSI_H_

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/cbitvector.h"
#include "../util/socket.h"
#include "../util/connection.h"
#include "../hashing/cuckoo.h"
#include "../hashing/simple_hashing.h"
#include "../util/ot/kk-ot-extension.h"
#include <algorithm>
#include "../util/helpers.h"

static bool DETAILED_TIMINGS=0;

//#define DEBUG
//#define PRINT_INPUTS
//#define PRINT_BIN_CONTENT
//#define PRINT_OPRG_MASKS
//#define PRINT_RECEIVED_VALUES
//#define PRINT_CRF_EVAL
//#define PRINT_CLIENT_MAPPING
//#define ENABLE_STASH //TODO: enabling stash introduces errors. fix!

struct mask_rcv_ctx {
	uint8_t* rcv_buf;
	uint32_t nmasks;
	uint32_t maskbytelen;
	CSocket* sock;
};

struct query_ctx {
	GHashTable *map;
	uint8_t* result;
	uint32_t res_size;

	uint8_t* elements;
	uint32_t elebytelen;

	uint8_t* qhashes;
	uint32_t qneles;
	uint32_t hashbytelen;
};


uint32_t otpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebitlen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, double epsilon=1.2,
		bool detailed_timings=false);

uint32_t otpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** res_bytelen, crypto* crypt_env, CSocket* sock,  uint32_t ntasks, double epsilon=1.2,
		bool detailed_timings=false);


uint32_t otpsi_client(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles, uint32_t elebitlen, uint32_t maskbitlen,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, prf_state_ctx* prf_state, uint32_t** result);

void otpsi_server(uint8_t* elements, uint32_t neles, uint32_t nbins, uint32_t pneles, uint32_t elebitlen, uint32_t maskbitlen,
		crypto* crypt_env, CSocket* sock, uint32_t ntasks, prf_state_ctx* prf_state);

void oprg_client(uint8_t* hash_table, uint32_t nbins, uint32_t neles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, CSocket* sock, uint32_t nthreads, uint8_t* res_buf);
void oprg_server(uint8_t* hash_table, uint32_t nbins, uint32_t totaleles, uint32_t* nelesinbin, uint32_t elebitlen,
		uint32_t maskbitlen, crypto* crypt, CSocket* sock, uint32_t nthreads, uint8_t* res_buf);

void send_masks(uint8_t* masks, uint32_t nmasks, uint32_t maskbytelen, CSocket& sock);
void *receive_masks(void *ctx_tmp);

GHashTable* otpsi_create_hash_table(uint32_t elebytelen, uint8_t* hashes, uint32_t neles, uint32_t
		hashbytelen, uint32_t* perm);
void *otpsi_query_hash_table(void* ctx_tmp);

uint32_t otpsi_find_intersection(uint32_t** result, uint8_t* my_hashes,
		uint32_t my_neles, uint8_t* pa_hashes, uint32_t pa_neles, uint32_t hashbytelen, uint32_t* perm);

void print_bin_content(uint8_t* hash_table, uint32_t nbins, uint32_t elebytelen, uint32_t* nelesinbin, bool multi_values);

void evaluate_crf(uint8_t* result, uint8_t* masks, uint32_t nelements, uint32_t elebytelen, crypto* crypt);


uint32_t get_stash_size(uint32_t neles);

#endif /* OT_PSI_H_ */
