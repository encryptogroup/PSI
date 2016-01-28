/*
 * Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../typedefs.h"
#include "../socket.h"
#include "../thread.h"
#include "../cbitvector.h"
#include "../crypto/crypto.h"
#include "maskingfunction.h"


//#define DEBUG
//#define FIXED_KEY_AES_HASHING
//#define VERIFY_OT

const uint8_t	G_OT = 0x01;
const uint8_t 	C_OT = 0x02;
const uint8_t	R_OT = 0x03;
const uint8_t	S_OT = 0x04;
const uint8_t OCRS_OT = 0x05;
const uint8_t	RN_OT = 0x06;


typedef struct OTBlock_t {
	uint32_t blockid;
	uint32_t processedOTs;
	uint8_t* snd_buf;
	OTBlock_t* next;
} OTBlock;

#define NUMOTBLOCKS 1024
#define REGISTER_BITS AES_BITS
#define REGISTER_BYTES AES_BYTES


static void InitAESKey(AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys)
{
	uint8_t* pBufIdx = keybytes;
	for(uint32_t i=0; i<numkeys; i++ )
	{
		EVP_CIPHER_CTX_init(ctx+i);
		EVP_EncryptInit_ex(ctx+i, EVP_aes_128_ecb(), NULL, pBufIdx, ZERO_IV);

		pBufIdx += AES_BYTES;
	}
}
#ifdef FIXED_KEY_AES_HASHING
static const uint8_t fixedkeyseed[2*AES_BYTES] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, \
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
#endif


class OTExtensionSender {
/*
 * OT sender part
 * Input: 
 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
 * 
 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
 * Output: was the execution successful?
 */
  public:
	OTExtensionSender(uint32_t nSndVals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock, CBitVector& U, uint8_t* keybytes,
			CBitVector& x0, CBitVector& x1,	uint8_t type, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, U, keybytes, nbaseOTs);
		//m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		//m_nSockets = sock;
		//m_nU = U;
		//m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * 2);
		m_vValues[0] = x0;
		m_vValues[1] = x1;
		m_nBitLength = bitlength;
		m_bProtocol = type;
		//m_nCounter = 0;
		//m_nSymSecParam = symsecparam;
		//m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam);
		//m_lSendLock = new CLock;
		//InitAESKey(m_vKeySeeds, keybytes, m_nSymSecParam);
	};


	OTExtensionSender(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, uint8_t* keybytes, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, U, keybytes, nbaseOTs);
	};

	void Init(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, uint8_t* keybytes, uint32_t nbaseOTs) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		m_nU = U;
		m_nCounter = 0;
		m_cCrypto = crypt;
		m_nSymSecParam = m_cCrypto->get_seclvl().symbits;
		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
#ifdef AES256_HASH
		m_vKeySeeds = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * nbaseOTs);
		intrin_sequential_ks4(m_vKeySeeds, keybytes, (int) nbaseOTs);
#else
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * nbaseOTs);
		InitAESKey(m_vKeySeeds, keybytes, nbaseOTs);
#endif
		m_lSendLock = new CLock;


#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypto->init_aes_key(m_kCRFKey, XXLT.symbits, (uint8_t*) fixedkeyseed);
		//MPC_AES_KEY_INIT(m_kCRFKey);
		//MPC_AES_KEY_EXPAND(m_kCRFKey, fixedkeyseed);
#endif
	};

	~OTExtensionSender(){free(m_vKeySeeds);};
	bool send(uint32_t numOTs, uint32_t bitlength, CBitVector& s0, CBitVector& s1, uint8_t type, uint32_t numThreads, MaskingFunction* maskfct);
	bool send(uint32_t numThreads);

	bool OTSenderRoutine(uint32_t id, uint32_t myNumOTs);
	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t blocksize, uint8_t* ctr);
	void ProcessAndEnqueue(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs);
	void SendBlocks(uint32_t numThreads);
	//void HashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs);
	bool verifyOT(uint32_t myNumOTs);
	void MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs);



  protected:
	uint8_t m_bProtocol;
  	uint32_t m_nSndVals;
  	uint32_t m_nOTs;
  	uint32_t m_nBitLength;
  	uint32_t m_nCounter;
  	uint32_t m_nBlocks;
  	uint32_t m_nSymSecParam;
  	CSocket* m_nSockets;
  	CBitVector m_nU;
  	CBitVector* m_vValues;
  	MaskingFunction* m_fMaskFct;
#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeeds;
#else
  	AES_KEY_CTX* m_vKeySeeds;
#endif
  	OTBlock* m_sBlockHead;
  	OTBlock* m_sBlockTail;
  	CLock* m_lSendLock;
  	crypto* m_cCrypto;
#ifdef FIXED_KEY_AES_HASH_OPRG
  	AES_KEY_CTX* m_kCRFKey;
#endif

	class OTSenderThread : public CThread {
	 	public:
	 		OTSenderThread(uint32_t id, uint32_t nOTs, OTExtensionSender* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTSenderThread(){};
			void ThreadMain() {success = callback->OTSenderRoutine(senderID, numOTs);};
		private: 
			uint32_t senderID;
			uint32_t numOTs;
			OTExtensionSender* callback;
			bool success;
	};

};



class OTExtensionReceiver {
/*
 * OT receiver part
 * Input: 
 * nSndVals: perform a 1-out-of-nSndVals OT
 * nOTs: the number of OTs that shall be performed
 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1) 
 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
 * 
 * Output: was the execution successful?
 */
  public:
	OTExtensionReceiver(uint32_t nSndVals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock,
			uint8_t* keybytes, CBitVector& choices, CBitVector& ret, uint8_t protocol, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs);
		//m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		//m_nSockets = sock;
		m_nChoices = choices;
		m_nRet = ret;
		//m_nSeed = seed;
		m_nBitLength = bitlength;
		m_bProtocol = protocol;
		//m_nCounter = 0;
		//m_nSymSecParam = symsecparam;
		//m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam * nSndVals);
		//InitAESKey(m_vKeySeedMtx, keybytes, m_nSymSecParam * nSndVals);
	};
	OTExtensionReceiver(uint32_t nSndVals, crypto* crypt, CSocket* sock, uint8_t* keybytes, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs);
	};

	void Init(uint32_t nSndVals, crypto* crypt, CSocket* sock, uint8_t* keybytes, uint32_t nbaseOTs) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		//m_nKeySeedMtx = vKeySeedMtx;
		m_cCrypto = crypt;
		m_nSymSecParam = m_cCrypto->get_seclvl().symbits;


		m_nCounter = 0;
#ifdef AES256_HASH
		m_vKeySeedMtx = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * nbaseOTs * 2);
		intrin_sequential_ks4(m_vKeySeedMtx, keybytes, (int) nbaseOTs * 2);
#else
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * nbaseOTs * 2);
		InitAESKey(m_vKeySeedMtx, keybytes, nbaseOTs * 2);
#endif

		m_nSeed = (uint8_t*) malloc(sizeof(AES_BYTES)); //
		m_cCrypto->gen_rnd(m_nSeed, AES_BYTES);//seed;
		m_lRcvLock = new CLock;

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypto->init_aes_key(m_kCRFKey, XXLT.symbits, (uint8_t*) fixedkeyseed);
		//m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		//MPC_AES_KEY_INIT(m_kCRFKey);
		//MPC_AES_KEY_EXPAND(m_kCRFKey, fixedkeyseed);
#endif
	}

	~OTExtensionReceiver(){free(m_vKeySeedMtx); };

	bool receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret, uint8_t type,
			uint32_t numThreads, MaskingFunction* maskfct);

	bool receive(uint32_t numThreads);
	bool OTReceiverRoutine(uint32_t id, uint32_t myNumOTs);
	//void ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, uint32_t id, uint32_t ctr, uint32_t lim);
	void ReceiveAndProcess(uint32_t numThreads);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, uint8_t* ctr_buf);
	void HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t lim);
	bool verifyOT(uint32_t myNumOTs);

  protected:
	uint8_t m_bProtocol;
  	uint32_t m_nSndVals;
  	uint32_t m_nOTs;
  	uint32_t m_nBitLength;
  	uint32_t m_nCounter;
  	uint32_t m_nSymSecParam;
  	CSocket* m_nSockets;
  	CBitVector m_nChoices;
  	CBitVector m_nRet;
  	CBitVector m_vTempOTMasks;
  	uint8_t* m_nSeed;
  	MaskingFunction* m_fMaskFct;
#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeedMtx;
#else
  	AES_KEY_CTX* m_vKeySeedMtx;
#endif
  	crypto* m_cCrypto;
  	CLock* m_lRcvLock;
#ifdef FIXED_KEY_AES_HASHING
  	AES_KEY_CTX* m_kCRFKey;
#endif


	class OTReceiverThread : public CThread {
	 	public:
	 		OTReceiverThread(uint32_t id, uint32_t nOTs, OTExtensionReceiver* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTReceiverThread(){};
			void ThreadMain() {success = callback->OTReceiverRoutine(receiverID, numOTs);};
		private: 
			uint32_t receiverID;
			uint32_t numOTs;
			OTExtensionReceiver* callback;
			bool success;
	};

};

#ifdef FIXED_KEY_AES_HASHING
inline void FixedKeyHashing(AES_KEY_CTX* aeskey, uint8_t* outbuf, uint8_t* inbuf, uint8_t* tmpbuf, uint32_t id, uint32_t bytessecparam) {
	memset(tmpbuf, 0, AES_BYTES);
	memcpy(tmpbuf, (uint8_t*) (&id), sizeof(uint32_t));
	for(uint32_t i = 0; i < bytessecparam; i++) {
		tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
	}

	MPC_AES_ENCRYPT(aeskey, outbuf, tmpbuf);

	for(uint32_t i = 0; i < bytessecparam; i++) {
		outbuf[i] = outbuf[i] ^ inbuf[i];//todo: optimize
	}
}
#endif

#endif /* __OT_EXTENSION_H_ */
