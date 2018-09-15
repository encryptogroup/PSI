/*
 * baseOT.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef BASEOT_H_
#define BASEOT_H_

#include "../typedefs.h"
#include "../cbitvector.h"
#include "../socket.h"
#include <ctime>

#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>
#include "../crypto/crypto.h"

class BaseOT
{
	public:
		BaseOT(crypto* crypt, field_type ftype){m_cCrypto = crypt; m_cPKCrypto = crypt->gen_field(ftype); };
		virtual ~BaseOT(){delete m_cPKCrypto; };

		virtual void Sender(uint32_t nSndVals, uint32_t nOTs, CSocket* sock, uint8_t* ret) = 0;
		virtual void Receiver(uint32_t nSndVals, uint32_t uint32_t, CBitVector& choices, CSocket* sock, uint8_t* ret) = 0;

protected:

		crypto* m_cCrypto;
		pk_crypto* m_cPKCrypto;
		//int m_nSecParam;
		//fparams m_fParams;
		//int m_nFEByteLen;

		//Big *m_BA, *m_BB, *m_BP;
		//Big *m_X, *m_Y;

		//int m_nM, m_nA, m_nB, m_nC;

		void hashReturn(uint8_t* ret, uint32_t ret_len, uint8_t* val, uint32_t val_len, uint32_t ctr) {
			m_cCrypto->hash_ctr(ret, ret_len, val, val_len, ctr);
		}




};

#endif /* BASEOT_H_ */
