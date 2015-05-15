/*
 * MaskingFunction.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef MASKINGFUNCTION_H_
#define MASKINGFUNCTION_H_

#include "../cbitvector.h"
#include "../typedefs.h"
#include "../crypto/crypto.h"

class MaskingFunction
{

public:
	MaskingFunction(){};
	~MaskingFunction(){};

	virtual void	Mask(uint32_t progress, uint32_t len, CBitVector* values, CBitVector* snd_buf, uint8_t protocol)  = 0;
	virtual void 	UnMask(uint32_t progress, uint32_t len, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf,CBitVector& tmpmask, uint8_t version) = 0;
	virtual void  expandMask(CBitVector& out, uint8_t* sbp, uint32_t offset, uint32_t processedOTs, uint32_t bitlength) = 0;


protected:


};


#endif /* MASKINGFUNCTION_H_ */
