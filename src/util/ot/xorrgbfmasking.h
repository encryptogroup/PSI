/*
 * XORBFMasking.h
 *
 *  Created on: October 22, 2013
 *      Author: mzohner
 */


#ifndef XORRGBFMASKING_H_
#define XORRGBFMASKING_H_

#include "maskingfunction.h"

#define RGBF_SERVER 0x00
#define RGBF_CLIENT 0x01

inline bool GetBitRGBF(BYTE* data, int idx){
   // return (filter->data[(idx+filter->leadingZeroes) >> 3] & (1 << (7-((idx+filter->leadingZeroes) & 7))))==0?0:1;
	return !!(data[idx >> 3] & (1 << (7-(idx & 7))));
};

//A masking function for the random garbled Bloom filter protocol
class XORRGBFMasking : public MaskingFunction
{
public:
	XORRGBFMasking(int bitlength, uint8_t id, uint8_t* choices, int leadingZeros)
	{init(bitlength); m_bID = id; m_vChoices.AttachBuf(choices, bitlength); m_nLeadingZeros = leadingZeros;};
	~XORRGBFMasking(){};


	void init(int bitlength)
	{
		if(!(bitlength>>3))
		{
			cerr << "BitLength must be a multiple of 8!" << endl;
			exit(0);
		}
		m_nByteLength = bitlength/8;
	}


	void Mask(int progress, int processedOTs, CBitVector* values, CBitVector* snd_buf, BYTE protocol)
	{
		//A hack write data into a fixed-size 2 dimensional out-bitvector for the GBF PSI protocl
		BYTE** outptr = ((BYTE**) (values[0].GetArr()))+progress;
		BYTE** limptr = outptr+processedOTs;
		BYTE* srcptr = snd_buf[0].GetArr();
		BYTE* data = m_vChoices.GetArr();
		for(int i = progress+m_nLeadingZeros, j; outptr<limptr; outptr++, srcptr++, i++)
		{
			//if(m_vChoices.GetBitNoMask(i))
			if(GetBitRGBF(data, i))
			{
				memcpy(outptr[0], srcptr, m_nByteLength);
			}
		}
	};

	//output already has to contain the masks
	void UnMask(int progress, int processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, CBitVector& tmpmask,  BYTE protocol)
	{
		/* Do nothing*/
	};

	void expandMask(CBitVector& out, BYTE* sbp, int offset, int processedOTs, int bitlength)
	{
		if(m_bID == RGBF_CLIENT)
		{
			//A hack write data into a fixed-size 2 dimensional out-bitvector for the GBF PSI protocl
			BYTE** outptr = ((BYTE**) (out.GetArr())) + offset;
			BYTE** limptr = outptr+processedOTs;
			BYTE* srcptr = sbp;
			BYTE* data = m_vChoices.GetArr();
			int bytelen = bitlength>>3;
			//for(int i = offset; i < offset+processedOTs; srcptr++, i++)
			for(int i = offset+m_nLeadingZeros; outptr<limptr; outptr++, srcptr++, i++)
			{
				if(GetBitRGBF(data, i))
				{
				//if(m_vChoices.GetBitNoMask(i))
					memcpy(outptr[0], srcptr, bytelen);
				}
			}
		} else {
			memcpy(out.GetArr(), sbp, (bitlength * processedOTs)>>3);
		}
	}

private:
	uint8_t** m_vDelta;
	int m_nByteLength;
	uint8_t m_bID;
	CBitVector m_vChoices;
	int m_nLeadingZeros;
};

#endif /* XORRGBFMASKING_H_ */
