/*
 * Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_1N_H_
#define __OT_EXTENSION_1N_H_

#include "../typedefs.h"
#include "../socket.h"
#include "../thread.h"
#include "../cbitvector.h"
#include "../crypto/crypto.h"
#include "../ecc.h"
#include "naor-pinkas.h"


//#define DEBUG_HASH_INPUT
//#define DEBUG_PRG_OUTPUT
//#define DEBUG_HASH_OUTPUT
//#define BILLION_SET


static void InitAESKey(AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys, crypto* crypt)
{
	uint8_t* pBufIdx = keybytes;
	for(uint32_t i=0; i<numkeys; i++ )
	{
		crypt->init_aes_key(ctx + i, pBufIdx);

		pBufIdx += AES_BYTES;
	}
}

class KKOTExtSnd {

	/*
		baseOTs = 256;
		N_bits = bit length of elements in bin
		crypt = reference to crypto object (initialized with 128-bit security parameter)
		sock = socket that is used for internal communication
	*/
  public:
	KKOTExtSnd(uint32_t baseOTs, uint32_t N_bits, crypto* crypt, CSocket* sock) {
		m_nBaseOTs = baseOTs;
		m_nSockets = sock;
		m_nCounter = 0L;
		m_cCrypto = crypt;
		m_nN_bytes = ceil_divide(N_bits, 8);


		//Initialize and compute the base-OTs
#ifdef AES256_HASH
		m_vKeySeeds = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * m_nBaseOTs);
#else
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs);
#endif
		m_nU.Create(m_nBaseOTs);
		crypt->gen_rnd(m_nU.GetArr(), ceil_divide(m_nBaseOTs, 8));

		NPBaseOTReceiver();

		//initialize the error-correcting code
		code = new ECC();
	};

	~KKOTExtSnd(){
		free(m_vKeySeeds);
		delete code;
	};

	void NPBaseOTReceiver();

	/*
		numOTs = number of bins
		bitlength = output bit length of masks
		hash_table = @Alex: needs to be replaced with path to file where hash table is stored
		results = @Alex: needs to be replaced with path to file where results are stored
		numThreads = number of threads that are run in parallel
		nelesinbin = array with number of elements in the i-th bin 
	*/

	bool send(uint64_t numOTs, uint32_t bitlength, CBitVector* hash_table, CBitVector* results, uint32_t numThreads, uint32_t* nelesinbin);
	bool send(uint32_t numThreads);

	bool OTSenderRoutine(uint64_t id, uint64_t myNumOTs);
	void BuildMatrix(CBitVector& T, CBitVector& RcvBuf, uint64_t blocksize, uint64_t ctr);
	void HashValues(CBitVector& Q, uint64_t ctr, uint64_t processedOTs);

  private:
	//Sender and Receiver Common Variables
	ECC* code;
	uint64_t* m_vStartingPosForBin;
  	uint64_t m_nOTs;
  	uint64_t m_nCounter;
	uint32_t m_nN_bytes;
	uint32_t* m_vNumEleInBin;
  	uint32_t m_nBaseOTs;
  	uint32_t m_nOutByteLength;
  	CSocket* m_nSockets;
  	crypto* m_cCrypto;

  	//Sender Variables
  	CBitVector m_nU;
  	CBitVector* m_vHashTable;
  	CBitVector* m_vOutput;
#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeeds;
#else
  	AES_KEY_CTX* m_vKeySeeds;
#endif

	class OTSenderThread : public CThread {
	 	public:
	 		OTSenderThread(uint64_t id, uint64_t nOTs, KKOTExtSnd* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTSenderThread(){};
			void ThreadMain() {success = callback->OTSenderRoutine(senderID, numOTs);};
		private: 
			uint64_t senderID;
			uint64_t numOTs;
			KKOTExtSnd* callback;
			bool success;
	};

};



class KKOTExtRcv {
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

	/*
		baseOTs = 256;
		N_bits = bit length of elements in bin
		crypt = reference to crypto object (initialized with 128-bit security parameter)
		sock = socket that is used for internal communication
	*/

	KKOTExtRcv(uint32_t baseOTs, uint32_t N_bits, crypto* crypt, CSocket* sock)  {
		m_nBaseOTs = baseOTs;
		m_nSockets = sock;
		m_cCrypto = crypt;
		m_nCounter = 0L;
		m_nN_bytes = ceil_divide(N_bits, 8);


		//Initialize and compute the base-OTs
#ifdef AES256_HASH
		m_vKeySeedMtx = (ROUND_KEYS*) malloc(sizeof(ROUND_KEYS) * m_nBaseOTs * 2);
#else
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs * 2);
#endif
		NPBaseOTSender();

		//Initialize the error-correcting code routines
		code = new ECC();
	};

	~KKOTExtRcv() {
		free(m_vKeySeedMtx);
		delete code;
	};

	void NPBaseOTSender();

	/*
		numOTs = number of bins
		bitlength = output bit length of masks
		choices = @Alex: needs to be replaced with path to file where hash table is stored
		ret = @Alex: needs to be replaced with path to file where results are stored
		numThreads = number of threads that are run in parallel
		nelesinbin = array with number of elements in the i-th bin (for the receiver either 0 or 1). 
	*/

	bool receive(uint64_t numOTs, uint32_t bitlength, CBitVector* choices, CBitVector* ret,
			uint32_t numThreads, uint32_t* numelesinbin);

	bool receive(uint32_t numThreads);

	bool OTReceiverRoutine(uint64_t id, uint64_t myNumOTs);
	void GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint64_t ctr, uint64_t lim);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks, uint64_t ctr);
	void HashValues(CBitVector& T, uint64_t ctr, uint64_t lim);


  private:
	//Sender and Receiver Common Variables
	ECC* code;
  	uint64_t m_nOTs;
  	uint64_t m_nCounter;
	uint64_t* m_vStartingPosForBin;
	uint32_t m_nN_bytes;
	uint32_t* m_vNumEleInBin;
  	uint32_t m_nBaseOTs;
  	uint32_t m_nOutByteLength;
  	CSocket* m_nSockets;
  	crypto* m_cCrypto;


  	//Receiver Variables
  	CBitVector* m_vHashTable;
  	CBitVector* m_vOutput;

#ifdef AES256_HASH
  	ROUND_KEYS* m_vKeySeedMtx;
#else
  	AES_KEY_CTX* m_vKeySeedMtx;
#endif

	class OTReceiverThread : public CThread {
	 	public:
	 		OTReceiverThread(uint64_t id, uint64_t nOTs, KKOTExtRcv* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTReceiverThread(){};
			void ThreadMain() {success = callback->OTReceiverRoutine(receiverID, numOTs);};
		private: 
			uint64_t receiverID;
			uint64_t numOTs;
			KKOTExtRcv* callback;
			bool success;
	};

};

#endif
