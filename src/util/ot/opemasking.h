/*
 * XORMasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef OPEMASKING_H_
#define OPEMASKING_H_

#include "maskingfunction.h"

//#define DEBUG_HASH_INPUT
//#define DEBUG_HASH_OUTPUT
//#define FIXED_KEY_AES_HASH_OPRG

#ifdef FIXED_KEY_AES_HASH_OPRG
static const uint8_t fixedkeyseed[AES_BYTES] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
#endif

class OPEMasking : public MaskingFunction
{
public:
	//Constructor that is called by the server
	OPEMasking(uint32_t itembitlen, uint32_t maskbitlen, uint32_t nbins, uint32_t* nelements,  CBitVector& server_choices, CBitVector& results, crypto* crypt) {
		m_vServerChoices = server_choices;
		m_vNumEleInBin = nelements;
		init(itembitlen, maskbitlen, results, crypt, true);
		InitAndReadCodeWord(&m_vCodeWords);
		m_vStartingPosForBin = (uint32_t*) malloc(sizeof(uint32_t) * nbins);
		assert(nbins > 0);
		m_vStartingPosForBin[0] = 0;
		m_nExpansionFactor = 1;
		if(m_vNumEleInBin[0] > m_nCodeWordBits) {
			m_nExpansionFactor = m_nCodeWordBits;
		}
		for(uint32_t i = 1; i < nbins; i++) {
			m_vStartingPosForBin[i] = m_vStartingPosForBin[i-1] + m_vNumEleInBin[i-1];
			if(m_vNumEleInBin[i] > m_nCodeWordBits) {
				m_nExpansionFactor = m_nCodeWordBits;
			}
		}

	};

	//Constructor that is called by the client
	OPEMasking(uint32_t itembitlen, uint32_t maskbitlen, uint32_t nbins, uint32_t* nelements, CBitVector& results, crypto* crypt)
	{
		init(itembitlen, maskbitlen, results, crypt, false);

		m_vNumEleInBin = nelements;
		m_vBinToResult = (uint32_t*) calloc(nbins, sizeof(uint32_t));

		for(uint32_t i = 1; i < nbins; i++) {
			m_vBinToResult[i] = m_vBinToResult[i-1] + m_vNumEleInBin[i-1];
		}
	};

	~OPEMasking(){
		//TODO id whether client or server routine is used
	};

	void init(uint32_t itembitlen, uint32_t maskbitlen,  CBitVector& results, crypto* crypt, bool server)
	{
		m_nItemBitLen = itembitlen;
		m_nMaskBitLen = maskbitlen;
		m_vResults = results;
		m_cCrypto = crypt;
		m_bServer = server;
		m_nOTsPerElement = ceil_divide(m_nItemBitLen, 8);
#ifdef FIXED_KEY_AES_HASH_OPRG
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypto->init_aes_key(m_kCRFKey, (uint8_t*) fixedkeyseed, ECB);
		//MPC_AES_KEY_INIT(m_kCRFKey);
		//MPC_AES_KEY_EXPAND(m_kCRFKey, fixedkeyseed);
#endif
	}

	//Expansion routine for the server
	void ServerExpand(CBitVector& matrix, uint8_t* uptr, uint32_t ot_begin_id, uint32_t processedOTs) {
		uint64_t ot_id, bin_id, bit_id, u, binoffset;
		uint32_t hashinbytes = m_nCodeWordBytes + sizeof(uint64_t);
		uint8_t *Mptr = matrix.GetArr();
		CBitVector mask(m_nCodeWordBits * m_nExpansionFactor);
		uint8_t* hash_buf = (uint8_t*) malloc(m_nCodeWordBytes * m_nExpansionFactor);
		uint8_t* mask_ptr;
		uint8_t* hash_ptr;
		uint8_t* tmpbuf = (uint8_t*) calloc(hashinbytes, sizeof(uint8_t));

#ifdef AES256_HASH
	AES_KEY tk_aeskey;
	block inblock, outblock;
	tk_aeskey.rounds = 14;
#endif

		//m_vServerChoices.PrintHex();
		for(ot_id = ot_begin_id; ot_id < ot_begin_id+processedOTs; ot_id++, Mptr+=m_nCodeWordBytes)
		{
			bin_id = ot_id/m_nOTsPerElement;
			bit_id = ot_id%m_nOTsPerElement;

			binoffset = m_vStartingPosForBin[bin_id] * m_nOTsPerElement;

			mask_ptr = mask.GetArr();

#ifdef AES256_HASH
			memcpy(tmpbuf, (uint8_t*) &ot_id, sizeof(uint64_t));
#endif

			if(m_vNumEleInBin[bin_id] < m_nCodeWordBits) {
				//cout << "Choice for ot_id = " << ot_id << ": ";
				for(u = 0; u < m_vNumEleInBin[bin_id]; u++)
				{
					//cout << "Server expanding for bin_id : " << bin_id << " and element id " << u << endl;
					mask.Copy(uptr, 0, m_nCodeWordBytes);
					//mask.ANDBytes((uint8_t*) m_vCodeWords[m_vServerChoices[bin_id].Get<uint32_t>((bit_id + u* m_nOTsPerElement) * 8, 8)], 0, m_nCodeWordBytes);
					mask.ANDBytes((uint8_t*) m_vCodeWords[m_vServerChoices.Get<uint32_t>((binoffset + bit_id + u* m_nOTsPerElement) * 8, 8)], 0, m_nCodeWordBytes);
					//cout << (hex) << m_vServerChoices[bin_id].Get<uint32_t>((bit_id + u* m_nOTsPerElement) * 8, 8) << (dec) << " ";
					mask.XORBytes(Mptr, m_nCodeWordBytes);
	#ifdef DEBUG_HASH_INPUT
					cout << "hash input for ot_id = " << ot_id <<" and choice = " << (hex) <<
							m_vServerChoices.Get<uint32_t>((binoffset + bit_id + u* m_nOTsPerElement) * 8, 8) << (dec) <<": ";
					mask.PrintHex();
	#endif
	#ifdef AES256_HASH
					//((uint64_t*) mask_ptr)[0] ^= ot_id;
					//m_cCrypto->aes_compression_hash(m_kCRFKey, hash_buf, mask_ptr, m_nCodeWordBytes);
					AES_256_Key_Expansion(mask_ptr, &tk_aeskey);
					inblock = _mm_loadu_si128((__m128i const*)(tmpbuf));
					AES_encryptC(&inblock, &outblock, &tk_aeskey);
					_mm_storeu_si128((__m128i *)(hash_buf), outblock);
	#else
					memcpy(tmpbuf, (uint8_t*) &ot_id, sizeof(uint64_t));
					memcpy(tmpbuf+sizeof(uint64_t), mask_ptr, m_nCodeWordBytes);
					m_cCrypto->hash(hash_buf, AES_BYTES, tmpbuf, hashinbytes);
					//m_cCrypto->hash_ctr(hash_buf, AES_BYTES, mask_ptr, m_nCodeWordBytes, ot_id);
	#endif
				//	cout << "MaskBitLen: " << m_nMaskBitLen << ", results size = " << m_vResults[bin_id].GetSize() <<  endl;
					//cout << "(" << (hex) << ((uint64_t*) hash_buf)[0] << ") " << (dec);
	#ifdef DEBUG_HASH_OUTPUT
					cout  << "hash output for ot_id = " << ot_id << " and element_id = " << u << ": ";
					for(uint32_t j = 0; j < AES_BYTES; j++)
						cout << (hex) << (unsigned int) hash_buf[j];
					cout << (dec) << endl;
	#endif
					//TODO: permute the values at this point - write into a permuted index
					m_vResults.XORBits(hash_buf, ((uint64_t) m_vStartingPosForBin[bin_id] + u) * m_nMaskBitLen, (uint64_t) m_nMaskBitLen);
					//m_vResults[bin_id].PrintHex();
				}
			} else {
				for(u = 0; u < m_nCodeWordBits; u++) {
					mask.Copy(uptr, u*m_nCodeWordBytes, m_nCodeWordBytes);
					mask.ANDBytes((uint8_t*) m_vCodeWords[u], u*m_nCodeWordBytes, m_nCodeWordBytes);
					mask.XORBytes(Mptr, (uint64_t) u*m_nCodeWordBytes, (uint64_t) m_nCodeWordBytes);
				}

				for(u = 0, hash_ptr=hash_buf, mask_ptr=mask.GetArr(); u < m_nCodeWordBits; u++, mask_ptr+=m_nCodeWordBytes, hash_ptr+=AES_BYTES) {
#ifdef AES256_HASH
					//((uint32_t*) mask_ptr)[0] ^= ot_id;
					//m_cCrypto->aes_compression_hash(m_kCRFKey, hash_ptr, mask_ptr, m_nCodeWordBytes);
					AES_256_Key_Expansion(mask_ptr, &tk_aeskey);
					inblock = _mm_loadu_si128((__m128i const*)(tmpbuf));
					AES_encryptC(&inblock, &outblock, &tk_aeskey);
					_mm_storeu_si128((__m128i *)(hash_ptr), outblock);
#else
					memcpy(tmpbuf, (uint8_t*) &ot_id, sizeof(uint64_t));
					memcpy(tmpbuf+sizeof(uint64_t), mask_ptr, m_nCodeWordBytes);
					m_cCrypto->hash(hash_ptr, AES_BYTES, tmpbuf, hashinbytes);
					//m_cCrypto->hash_ctr(hash_ptr, AES_BYTES, mask_ptr, m_nCodeWordBytes, ot_id);
#endif
#ifdef DEBUG_HASH_OUTPUT
					cout  << "hash output for ot_id = " << ot_id << " and element_id = " << u << ": ";
					for(uint32_t j = 0; j < AES_BYTES; j++)
						cout << (hex) << (unsigned int) hash_buf[j];
					cout << (dec) << endl;
#endif
				}
				uint64_t mask_id;
				for(u = 0; u < m_vNumEleInBin[bin_id]; u++) 	{
					mask_id = m_vServerChoices.Get<uint32_t>((binoffset + bit_id + u* m_nOTsPerElement) * 8, 8);
					m_vResults.XORBits(hash_buf+mask_id*AES_BYTES, ((uint64_t) m_vStartingPosForBin[bin_id] + u) * m_nMaskBitLen, (uint64_t) m_nMaskBitLen);
				}
			}

			//cout << endl;
		}
		mask.delCBitVector();
		free(hash_buf);
		free(tmpbuf);
	}

	//Expansion routine for the client
	void ClientExpand(CBitVector& matrix, uint32_t ot_begin_id, uint32_t processedOTs) {
		//uint8_t hash_buf[m_cCrypto->get_hash_bytes()];
		uint64_t ot_id, bin_id;
		uint32_t hashinbytes = m_nCodeWordBytes + sizeof(uint64_t);
		uint8_t *Mptr = matrix.GetArr();
		uint8_t* hash_buf = (uint8_t*) malloc(m_nCodeWordBytes);
		uint8_t* tmpbuf = (uint8_t*) calloc(hashinbytes, sizeof(uint8_t));

#ifdef AES256_HASH
	AES_KEY tk_aeskey;
	block inblock, outblock;
	tk_aeskey.rounds = 14;

#endif

		for(ot_id = ot_begin_id; ot_id < ot_begin_id+processedOTs; ot_id++, Mptr+=m_nCodeWordBytes)
		{

#ifdef AES256_HASH
			memcpy(tmpbuf, (uint8_t*) &ot_id, sizeof(uint64_t));
#endif
			bin_id = ot_id/m_nOTsPerElement;
			if(m_vNumEleInBin[bin_id] > 0) {
#ifdef DEBUG_HASH_INPUT
				cout << "hash input for ot_id = " << ot_id << ": ";
				for(uint32_t j = 0; j < m_nCodeWordBytes; j++)
					cout << (hex) << (unsigned int) Mptr[j];
				cout << endl;
#endif

#ifdef AES256_HASH
				//((uint64_t*) Mptr)[0] ^= ot_id;
				//m_cCrypto->aes_compression_hash(m_kCRFKey, hash_buf, Mptr, m_nCodeWordBytes);
				AES_256_Key_Expansion(Mptr, &tk_aeskey);
				inblock = _mm_loadu_si128((__m128i const*)(tmpbuf));
				AES_encryptC(&inblock, &outblock, &tk_aeskey);
				_mm_storeu_si128((__m128i *)(hash_buf), outblock);
#else
				memcpy(tmpbuf, (uint8_t*) &ot_id, sizeof(uint64_t));
				memcpy(tmpbuf+sizeof(uint64_t), Mptr, m_nCodeWordBytes);
				m_cCrypto->hash(hash_buf, AES_BYTES, tmpbuf, hashinbytes);
				//m_cCrypto->hash_ctr(hash_buf, AES_BYTES, Mptr, m_nCodeWordBytes, ot_id);
#endif

			//	cout << "Client expanding for bin_id : " << bin_id << endl;
			//	cout << "MaskBitLen: " << m_nMaskBitLen << endl;
				m_vResults.XORBits(hash_buf, ((uint64_t) m_vBinToResult[bin_id]) * m_nMaskBitLen, (uint64_t) m_nMaskBitLen);
				//m_vResults[bin_id].PrintHex();
				//cout << "otid = " << ot_id << ": " << (hex) << ((uint64_t*) hash_buf)[0] << (dec) << endl;
#ifdef DEBUG_HASH_OUTPUT
				cout << "hash output for ot_id = " << ot_id << ": ";
				for(uint32_t j = 0; j < AES_BYTES; j++)
					cout << (hex) << (uint32_t) hash_buf[j];
				cout << (dec) << ", " << (ot_begin_id) << ", " << processedOTs << ", " << m_nCodeWordBytes << ", " << (uint64_t) Mptr << endl;
#endif
			}
		}
		free(hash_buf);
		free(tmpbuf);
	}

	//the out vector contains the matrix with the data that needs to be hashed, uptr is a pointer to the choice-bits of the server in the base-OTs
	void expandMask(CBitVector& matrix, uint8_t* uptr, uint32_t ot_begin_id, uint32_t processedOTs, uint32_t bitlength) {
		if(m_bServer) {
			ServerExpand(matrix, uptr, ot_begin_id, processedOTs);
		} else {
			ClientExpand(matrix, ot_begin_id, processedOTs);
		}
	}

	//Do nothing, only dummy function to implement virtual function
	void Mask(uint32_t progress, uint32_t processedOTs, CBitVector* values, CBitVector* snd_buf,
			uint8_t protocol)	{};


	//TODO: update, not working any more since unmask was changed
	void UnMask(uint32_t progress, uint32_t processedOTs, CBitVector& choices, CBitVector& output,
			CBitVector& rcv_buf, CBitVector& tempmasks, uint8_t protocol) { };

private:
	uint32_t m_nItemBitLen;
	uint32_t m_nMaskBitLen;
	uint32_t m_nOTsPerElement;
	uint8_t m_bBuf[AES_BYTES];
	uint8_t ctr_buf[AES_BYTES];
	uint32_t* m_vBinToResult;
	uint32_t* m_vNumEleInBin;
	uint32_t* m_vStartingPosForBin;
	CBitVector m_vServerChoices;
	CBitVector m_vResults;
	crypto* m_cCrypto;
	uint32_t m_nExpansionFactor;
	bool m_bServer;
	REGISTER_SIZE** m_vCodeWords;
#ifdef FIXED_KEY_AES_HASH_OPRG
	AES_KEY_CTX*  m_kCRFKey;
#endif
};

#endif /* OPEMASKING_H */
