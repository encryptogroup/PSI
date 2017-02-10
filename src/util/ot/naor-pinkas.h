/*
 * Compute the Naor-Pinkas Base OTs
 */

#ifndef __Naor_Pinkas_H_
#define __Naor_Pinkas_H_

#include "baseOT.h"

class NaorPinkas : public BaseOT
{

	public:

	NaorPinkas(crypto* crypto, field_type ftype) : BaseOT(crypto, ftype) {};
	~NaorPinkas(){};

	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector& choices, CSocket* sock, uint8_t* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, CSocket* sock, uint8_t* ret);

	
};
		


#endif
