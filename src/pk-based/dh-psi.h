/*
 * dh-psi.h
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */

#ifndef DH_PSI_H_
#define DH_PSI_H_


#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"


uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality=false, field_type ftype=ECC_FIELD);

uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality=false,
		field_type ftype=ECC_FIELD);


uint32_t dhpsi(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, uint32_t* matches, bool cardinality=false, field_type ftype=ECC_FIELD);


#endif /* DH_PSI_H_ */
