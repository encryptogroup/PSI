/*
 * XORMasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef XORMASKING_H_
#define XORMASKING_H_

#include "maskingfunction.h"

class XORMasking : public MaskingFunction
{
public:
	XORMasking(int bitlength, crypto* crypt){init(bitlength, crypt); };
	XORMasking(int bitlength, crypto* crypt, CBitVector& delta) { m_vDelta = &delta; init(bitlength, crypt);};
	~XORMasking(){};


	void init(int bitlength, crypto* crypt)
	{
		m_nBitLength = bitlength;
		m_cCrypto = crypt;
	}

	void Mask(uint32_t progress, uint32_t processedOTs, CBitVector* values, CBitVector* snd_buf, uint8_t protocol)
	{
		uint32_t nsndvals = 2;

		if(protocol == G_OT)
		{
			snd_buf[0].XORBytes(values[0].GetArr() + ceil_divide(progress * m_nBitLength, 8), (uint64_t) 0, ceil_divide(((uint64_t) processedOTs) * m_nBitLength, 8));
			snd_buf[1].XORBytes(values[1].GetArr() + ceil_divide(progress * m_nBitLength, 8), (uint64_t) 0, ceil_divide(((uint64_t) processedOTs) * m_nBitLength, 8));
		}
		else if(protocol == C_OT)
		{
			values[0].SetBytes(snd_buf[0].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));//.SetBits(hash_buf, i*m_nBitLength, m_nBitLength);
			uint64_t bitPos = ((uint64_t) progress) * m_nBitLength;
			uint64_t length = ((uint64_t) processedOTs) * m_nBitLength;
			uint64_t bytePos = ceil_divide(bitPos, 8);

			//cout << "Performing masking for " << bytePos << " and " << bitPos << " to " << length << "(" << m_nBitLength << ", " << processedOTs << ")"<< endl;
			values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
			values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);
			snd_buf[1].XORBits(values[1].GetArr() + bytePos, (uint64_t) 0, length);
		}
		else if(protocol == R_OT)
		{
			values[0].SetBytes(snd_buf[0].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
			values[1].SetBytes(snd_buf[1].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
		}
		/*int bitPos = progress * m_nBitLength;
		int length = processedOTs * m_nBitLength;
		int bytePos = CEIL_DIVIDE(bitPos, 8);

		//cout << "Performing masking for " << bytePos << " and " << bitPos << " to " << length << "(" << m_nBitLength << ", " << processedOTs << ")"<< endl;
		values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
		values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);

		snd_buf.XORBits(values[1].GetArr() + bytePos, 0, length);*/
	};

	//output already has to contain the masks
	void UnMask(uint32_t progress, uint32_t processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, CBitVector& tmpmask, uint8_t protocol)
	{
		uint32_t bytelen = ceil_divide(m_nBitLength, 8);
		uint32_t gprogress = progress * bytelen;
		//int gprogress = progress * m_nBitLength;
		uint32_t lim = progress + processedOTs;

		if(protocol == G_OT)
		{
			for(uint32_t u, i= progress, offset = processedOTs * bytelen, l = 0; i < lim; i++, gprogress+=bytelen, l+=bytelen)
			{
				//TODO make this working for single bits
				u = (int) choices.GetBitNoMask(i);
				output.SetXOR(rcv_buf.GetArr() + (u * offset) + l, tmpmask.GetArr() + gprogress, gprogress, bytelen);
				//output.SetBit(gprogress, tmpmask.GetBit(l));
				//output.XORBit(gprogress, rcv_buf.GetBit(u * offset + l));
			}

		}
		else if (protocol == C_OT || protocol == S_OT)
		{
			int gprogress = progress * bytelen;
			output.Copy(tmpmask.GetArr() + gprogress, gprogress, bytelen * processedOTs);
			for(uint32_t i = progress, l = 0; i < lim; i++, l+=bytelen, gprogress+=bytelen)
			{
				if(choices.GetBitNoMask(i))
				{
					//TODO make this working for single bits
					output.XORBytes(rcv_buf.GetArr() + l, gprogress, (int) bytelen);
					//output.XORBitsPosOffset(rcv_buf.GetArr(), l, progress*m_nBitLength, m_nBitLength);
				}
			}
		}
		else if(protocol == R_OT)
		{
			//The seed expansion has already been performed, so do nothing
		}
	};


	void expandMask(CBitVector& out, uint8_t* sbp, uint32_t offset, uint32_t processedOTs, uint32_t bitlength)
	{

		if(bitlength <= m_cCrypto->get_aes_key_bytes())
		{
			for(uint32_t i = 0; i< processedOTs; i++, sbp+=m_cCrypto->get_aes_key_bytes())
			{
			//	cout << "Setting bits from " << (offset + i) * bitlength << " with " << bitlength << " len " << endl;
				//cout << "Byte: " << ((unsigned int) sbp[0]) << ", bitlenh = " << bitlength << ", pos = " << (offset + i) * bitlength << ", ";

				out.SetBits(sbp, (offset + i) * bitlength, bitlength);
				//out.PrintBinary();

			}
			//cout << "Out = "<< endl;
			//out.PrintHex();
		}
		else
		{
			uint8_t m_bBuf[AES_BYTES];
			uint8_t ctr_buf[AES_BYTES] = {0};
			uint32_t counter = *((uint32_t*) ctr_buf);
			AES_KEY_CTX tkey;
			//MPC_AES_KEY_INIT(&tkey);
			for(uint32_t i = 0, rem; i< processedOTs; i++, sbp+=m_cCrypto->get_aes_key_bytes())
			{
				//MPC_AES_KEY_EXPAND(&tkey, sbp);
				m_cCrypto->init_aes_key(&tkey, sbp);
				for(counter = 0; counter < bitlength/AES_BITS; counter++)
				{
					m_cCrypto->encrypt(&tkey, m_bBuf, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					out.SetBits(m_bBuf, (offset+ i) * bitlength + (counter*AES_BITS), AES_BITS);
				}
				//the final bits
				//cout << "bits: " << (counter*AES_BITS) << ", bitlength: " << m_nBitLength << endl;
				if((rem = bitlength - (counter*AES_BITS)) > 0)
				{
					m_cCrypto->encrypt(&tkey, m_bBuf, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					out.SetBits(m_bBuf, (offset + i) * bitlength + (counter*AES_BITS), rem);
				}
			}
		}
	}

private:
	CBitVector* m_vDelta;
	int m_nBitLength;
	crypto* m_cCrypto;
};

#endif /* XORMASKING_H_ */
