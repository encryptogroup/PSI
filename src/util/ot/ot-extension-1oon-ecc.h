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
#include "maskingfunction.h"
#include "ot-extension.h"
#include "../crypto/crypto.h"




//TODO verification not working, fix
//#define ZDEBUG
//#define DEBUG_HASH_INPUT
//#define DEBUG_PRG_OUTPUT
//#define DEBUG_HASH_OUTPUT


class OTExtension1ooNECCSender : public OTExtensionSender {
/*
 * OT sender part
 * Input: 
 * ret: returns the resulting bit representations. Has to initialized to a uint8_t size of: nOTs * nSndVals * state.field_size
 * 
 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
 * Output: was the execution successful?
 */
  public:
	OTExtension1ooNECCSender(uint32_t sndvals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock, CBitVector& U, uint8_t* keybytes,
			CBitVector& x0, CBitVector& x1,	uint8_t type) : OTExtensionSender(sndvals, nOTs, bitlength, crypt, sock, U, keybytes, x0, x1, type, m_nCodeWordBits){
		InitAndReadCodeWord(&m_vCodeWords);
	};

	OTExtension1ooNECCSender(uint32_t nsndvals, crypto* crypt, CSocket* sock, CBitVector& U, uint8_t* keybytes) :
		OTExtensionSender(nsndvals, crypt, sock, U, keybytes, m_nCodeWordBits) {
		InitAndReadCodeWord(&m_vCodeWords);
	};

	bool send(uint32_t numOTs, uint32_t bitlength, CBitVector* values, uint8_t type, uint32_t numThreads, MaskingFunction* maskfct);
	bool send(uint32_t numThreads);

	bool OTSenderRoutine(uint32_t id, uint32_t myNumOTs);
	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t blocksize, uint8_t* ctr);
	void MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs);
	bool verifyOT(uint32_t myNumOTs);

  private:
	REGISTER_SIZE** m_vCodeWords;


	class OTSenderThread : public CThread {
	 	public:
	 		OTSenderThread(uint32_t id, uint32_t nOTs, OTExtension1ooNECCSender* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTSenderThread(){};
			void ThreadMain() {success = callback->OTSenderRoutine(senderID, numOTs);};
		private: 
			uint32_t senderID;
			uint32_t numOTs;
			OTExtension1ooNECCSender* callback;
			bool success;
	};

};



class OTExtension1ooNECCReceiver : public OTExtensionReceiver {
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
	OTExtension1ooNECCReceiver(uint32_t nsndvals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock,
			uint8_t* keybytes, CBitVector& choices, CBitVector& ret, uint8_t protocol) :
				OTExtensionReceiver(nsndvals, nOTs, bitlength, crypt, sock, keybytes, choices, ret, protocol, m_nCodeWordBits) {
		InitAndReadCodeWord(&m_vCodeWords);
	};
	OTExtension1ooNECCReceiver(uint32_t nsndvals, crypto* crypt, CSocket* sock, uint8_t* keybytes) :
		OTExtensionReceiver(nsndvals, crypt, sock, keybytes, m_nCodeWordBits) {
		InitAndReadCodeWord(&m_vCodeWords);
	};



	bool receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret, uint8_t type,
			uint32_t numThreads, MaskingFunction* maskfct);

	bool receive(uint32_t numThreads);
	bool OTReceiverRoutine(uint32_t id, uint32_t myNumOTs);
	//void ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, uint32_t id, uint32_t ctr, uint32_t lim);
	void GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint32_t ctr, uint32_t lim);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, uint8_t* ctr_buf);
	void HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t lim);
	bool verifyOT(uint32_t myNumOTs);


  private:
	REGISTER_SIZE** m_vCodeWords;

	class OTReceiverThread : public CThread {
	 	public:
	 		OTReceiverThread(uint32_t id, uint32_t nOTs, OTExtension1ooNECCReceiver* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTReceiverThread(){};
			void ThreadMain() {success = callback->OTReceiverRoutine(receiverID, numOTs);};
		private: 
			uint32_t receiverID;
			uint32_t numOTs;
			OTExtension1ooNECCReceiver* callback;
			bool success;
	};

};

#endif
