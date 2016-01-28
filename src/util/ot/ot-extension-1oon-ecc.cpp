#include "ot-extension-1oon-ecc.h"

bool OTExtension1ooNECCReceiver::receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret, uint8_t type, uint32_t numThreads, MaskingFunction* unmaskfct) {
		m_nOTs = numOTs;
		m_nBitLength = bitlength;
		m_nChoices = choices;
		m_nRet = ret;
		m_bProtocol = type;
		m_fMaskFct = unmaskfct;
		return receive(numThreads);
};

//Initialize and start numThreads OTSenderThread
bool OTExtension1ooNECCReceiver::receive(uint32_t numThreads)
{
	if(m_nOTs == 0)
		return true;

	if(m_bProtocol != R_OT && m_bProtocol != RN_OT) {
		cerr << "Only working with R_OT or RN_OT right now, sorry!" << endl;
		return false;
	}

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t internal_numOTs = ceil_divide(pad_to_multiple(m_nOTs, REGISTER_BITS), numThreads);
	//cout << "Internal num OTs: " << internal_numOTs << endl;
	//uint8_t go;
	//Wait for the signal of the corresponding sender thread
	//sock.Receive(&go, 1);

	vector<OTReceiverThread*> rThreads(numThreads); 
	for(uint32_t i = 0; i < numThreads; i++)
	{
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}

	for(uint32_t i = 0; i < numThreads; i++)
	{
		rThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(uint32_t i = 0; i < numThreads; i++)
		delete rThreads[i];

#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	uint8_t finished = 0x01;
	m_nSockets[0].Send(&finished, 1);

	verifyOT(m_nOTs);
#endif

	return true;
}



bool OTExtension1ooNECCReceiver::OTReceiverRoutine(uint32_t id, uint32_t myNumOTs)
{
	//cout << "Thread " << id << " started" << endl;
	uint32_t myStartPos = id * myNumOTs;
	uint32_t i = myStartPos;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos+myNumOTs;

	//How many batches of OTEXT_BLOCK_SIZE_BITS OTs should be performed?
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(myNumOTs, m_nCodeWordBits));
	//How many OTs should be performed per iteration
	uint32_t OTsPerIteration = processedOTBlocks * m_nCodeWordBits;
	uint32_t OTwindow = NUMOTBLOCKS*m_nCodeWordBits;
	CSocket* sock = m_nSockets+id;

	//counter variables
	uint32_t nSize;

	// A temporary part of the T matrix
	CBitVector T(m_nCodeWordBits * OTsPerIteration);
	T.Reset();
	// The send buffer
	CBitVector vSnd(m_nCodeWordBits * OTsPerIteration);
	// Stores the codes for the choice bits
	CBitVector choicecodes(m_nCodeWordBits * m_nCodeWordBits);
	choicecodes.Reset();
	// A temporary buffer that stores the resulting seeds from the hash buffer
	CBitVector seedbuf(OTwindow*AES_BITS);// = new CBitVector[RoundWindow];

	uint8_t ctr_buf[AES_BYTES] = {0};
	uint32_t* counter = (uint32_t*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef TIMING
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChcTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( i < lim )
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim-i, m_nCodeWordBits));
 		OTsPerIteration = processedOTBlocks * m_nCodeWordBits;

#ifdef TIMING
 		gettimeofday(&tempStart, NULL);
#endif
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalChcTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i, ctr_buf);
		GenerateChoiceCodes(choicecodes, vSnd, i, min(lim-i, OTsPerIteration));

#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		T.EklundhBitTranspose(m_nCodeWordBits, OTsPerIteration);
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		//cout << "offset: " << (AES_KEY_uint8_tS * (i-nProgress))<< ", i = " << i << ", nprogress = " << nProgress << ", otwindow = " << OTwindow << endl;
		HashValues(T, seedbuf, i, min(lim-i, OTsPerIteration));
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif

		nSize = m_nCodeWordBytes * OTsPerIteration;
 		//cout << "Sending " << nSize << " Bytes " << endl;
		//m_lRcvLock->Lock();
 		//cout << "(" << id << ") Sending " << nSize << " bytes on OT " << i << endl;
 		sock->Send( vSnd.GetArr(), nSize );
		//cout << "(" << id << ") sent " << nSize << " bytes for OT " << i << endl;
		//vSnd.PrintHex(0,1024);
		//m_lRcvLock->Unlock();
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		i+=min(lim-i, OTsPerIteration);
		//cout << "Performing next OTs " << i << ", OTsPerItation = " << OTsPerIteration << endl;

#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
#endif
 		vSnd.Reset();
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	choicecodes.delCBitVector();

#ifdef TIMING
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Generating Choice-Code:t" << totalChcTime << " ms" << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

	//sleep(1);
	return TRUE;
}

void OTExtension1ooNECCReceiver::GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint32_t startpos, uint32_t len) {
	uint32_t tmpchoice;
	uint32_t otid = startpos;
	uint32_t ncolumnsbyte = ceil_divide(len, m_nCodeWordBits) * m_nCodeWordBytes;
	for(uint32_t pos = 0; pos < len; pos+=m_nCodeWordBits) {
		choicecodes.Reset();
		for(uint32_t j = 0; j < min(len - pos, m_nCodeWordBits); j++, otid++) {
			tmpchoice = m_nChoices.Get<uint32_t>(otid * 8, 8);
			//cout << "otid = " << otid << ", choice = " << tmpchoice << endl;
#ifdef ZDEBUG
		cout << "my choice : " << tmpchoice << endl;
#endif
			choicecodes.SetBytes((uint8_t*) m_vCodeWords[tmpchoice], j*m_nCodeWordBytes, m_nCodeWordBytes);
		}
		choicecodes.EklundhBitTranspose(m_nCodeWordBits, m_nCodeWordBits);
		for(uint32_t j = 0; j < m_nCodeWordBits; j++) {
			vSnd.XORBytes(choicecodes.GetArr() + j * m_nCodeWordBytes, (pos >> 3) + j * ncolumnsbyte, m_nCodeWordBytes);
		//	cout << "accessing byte: " << (pos >> 3) + j * ncolumnsbyte << endl;
			/*cout << "S: ";
			for(uint32_t i = 0; i < m_nCodeWordBytes; i++) {
				cout << (hex) << (unsigned int)  *(vSnd.GetArr() + j * m_nCodeWordBytes + i);
			}
			cout << (dec) << endl;*/
		}
	}
}



void OTExtension1ooNECCReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, uint8_t* ctr_buf)
{
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint64_t tempctr = (*counter);

	uint8_t* Tptr = T.GetArr();
	uint8_t* sndbufptr = SndBuf.GetArr();


#ifdef AES256_HASH
	//first prg output written to tptr
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, Tptr, (int) 2*numblocks, (int) m_nCodeWordBits, m_vKeySeedMtx);

	//second prg output written to snd buffer
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, sndbufptr, (int) 2*numblocks, (int) m_nCodeWordBits, m_vKeySeedMtx+m_nCodeWordBits);

#else
	//cout << "Numblocks = " << numblocks << endl;
	for(uint32_t k = 0; k < m_nCodeWordBits; k++)
	{
		(*counter) = tempctr;
		for(uint32_t b = 0; b < 2*numblocks; b++, (*counter)++)
		{
			m_cCrypto->encrypt(m_vKeySeedMtx + 2*k, Tptr, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(m_vKeySeedMtx + 2*k, Tptr, ctr_buf);
			Tptr+=OTEXT_BLOCK_SIZE_BYTES;

			m_cCrypto->encrypt(m_vKeySeedMtx + 2*k + 1, sndbufptr, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(m_vKeySeedMtx + (2*k) + 1, sndbufptr, ctr_buf);
			sndbufptr+=OTEXT_BLOCK_SIZE_BYTES;
		}

#ifdef DEBUG_PRG_OUTPUT
		cout << "I: ";
		for(uint32_t i = 0; i < AES_BYTES; i++) {
			cout << (hex) << (unsigned int) *(ctr_buf + i);
		}
		cout << endl << "T: ";
		for(uint32_t i = 0; i < OTEXT_BLOCK_SIZE_BYTES*2; i++) {
			cout << (hex) << (unsigned int) *(Tptr-(2*OTEXT_BLOCK_SIZE_BYTES) + i);
		}
		cout << endl << "S: ";
		for(uint32_t i = 0; i < OTEXT_BLOCK_SIZE_BYTES*2; i++) {
			cout << (hex) << (unsigned int) *(sndbufptr-(2*OTEXT_BLOCK_SIZE_BYTES) + i);
		}
		cout << endl;
#endif
	}
#endif
	SndBuf.XORBytes(T.GetArr(), (uint32_t) 0, m_nCodeWordBytes*numblocks*m_nCodeWordBits);
}


void OTExtension1ooNECCReceiver::HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t processedOTs)
{
	//If OT-based PSI is performed, the hashing is skipped and the masking is called directly
	if(m_bProtocol == RN_OT) {
		m_fMaskFct->expandMask(T, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength); //m_sSecParam.statbits
		return;
	}

	uint8_t* Tptr = T.GetArr();
	uint8_t* bufptr = seedbuf.GetArr();//m_vSeedbuf.GetArr() + ctr * AES_KEY_uint8_tS;//seedbuf.GetArr();

	//HASH_CTX sha;
	uint8_t hash_buf[m_cCrypto->get_hash_bytes()];

#ifdef AES256_HASH
	AES_KEY tk_aeskey;
	block inblock, outblock;
	tk_aeskey.rounds = 14;
#endif

	for(uint32_t i = ctr; i < ctr+processedOTs; i++, Tptr+=m_nCodeWordBytes, bufptr+=AES_BYTES)
	{
#ifdef DEBUG_HASH_INPUT
		cout << "hash input for i = " << i << " and choice = " << (uint32_t) m_nChoices.Get<uint32_t>(i) << ": ";
		T.PrintHex((i-ctr) * m_nCodeWordBytes, (i-ctr+1) * m_nCodeWordBytes);
#endif
#ifdef AES256_HASH
		AES_256_Key_Expansion(Tptr, &tk_aeskey);
		inblock = _mm_loadu_si128((__m128i const*)(hash_buf));
		AES_encryptC(&inblock, &outblock, &tk_aeskey);
		_mm_storeu_si128((__m128i *)(bufptr), outblock);
#else 
		cout << "hashing" << endl;
		m_cCrypto->hash_ctr(bufptr, AES_BYTES, Tptr, m_nCodeWordBytes, i);
#endif

#ifdef DEBUG_HASH_OUTPUT
		cout << "hash output for i = " << i << " and choice = " << (uint32_t) m_nChoices.Get<uint32_t>(i) << ": ";
		for(uint32_t j = 0; j < AES_BYTES; j++)
			cout << (hex) << (unsigned int) bufptr[j];
		cout << (dec) << endl;
#endif
	}

	m_fMaskFct->expandMask(m_nRet, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength);


}


bool OTExtension1ooNECCReceiver::verifyOT(uint32_t NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vRcvX[m_nSndVals];
	for(uint32_t u = 0; u < m_nSndVals; u++) {
		vRcvX[u].Create(NUMOTBLOCKS*m_nCodeWordBits*m_nBitLength);
	}
	CBitVector* Xc;
	uint64_t processedOTBlocks, OTsPerIteration;
	uint64_t bytelen = ceil_divide(m_nBitLength, 8);
	uint8_t* tempXc = new uint8_t[bytelen];
	uint8_t* tempRet = new uint8_t[bytelen];
	uint8_t resp;
	for(uint64_t i = 0; i < NumOTs;) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(NumOTs-i, m_nCodeWordBits));
 		//OTsPerIteration = processedOTBlocks * Z_REGISTER_BITS;
		OTsPerIteration = min(processedOTBlocks * m_nCodeWordBits, NumOTs-i);
		for(uint32_t u = 0; u < m_nSndVals; u++) {
			sock.Receive(vRcvX[u].GetArr(), ceil_divide(m_nBitLength * OTsPerIteration, 8));
		}
		for(uint32_t j = 0; j < OTsPerIteration && i < NumOTs; j++, i++)
		{
			Xc = &(vRcvX[m_nChoices.Get<uint32_t>(i)]);

			Xc->GetBits(tempXc, j*m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i*m_nBitLength, m_nBitLength);
			for(uint32_t k = 0; k < bytelen; k++)
			{
				if(tempXc[k] != tempRet[k])
				{
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (uint32_t) m_nChoices.GetBitNoMask((uint64_t) i)
							<< " = " << (uint32_t) tempXc[k] << " and res = " << (uint32_t) tempRet[k] << (dec) << endl;
						//<< " = " << ((uint32_t*) (tempXc + k))[0] << " and res = " << ((uint32_t*) (tempRet + k))[0] << (dec) << endl;
					resp = 0x00;
					sock.Send(&resp, 1);
					return false;
				}
			}
		}
		resp = 0x01;
		sock.Send(&resp, 1);
	}
	delete[] tempXc;
	delete[] tempRet;

	for(uint32_t u = 0; u < m_nSndVals; u++)
		vRcvX[u].delCBitVector();
	cout << "OT Verification successful" << endl;
	return true;
}



bool OTExtension1ooNECCSender::send(uint32_t numOTs, uint32_t bitlength, CBitVector* values, uint8_t type,
		uint32_t numThreads, MaskingFunction* maskfct)
{
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues = values;
	m_bProtocol = type;
	m_fMaskFct = maskfct;
	return send(numThreads);
}


//Initialize and start numThreads OTSenderThread
bool OTExtension1ooNECCSender::send(uint32_t numThreads)
{
	if(m_nOTs == 0)
		return true;

	if(m_bProtocol != R_OT && m_bProtocol != RN_OT) {
		cerr << "Only working with R_OT or RN_OT right now, sorry!" << endl;
		return false;
	}


	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t numOTs = ceil_divide(pad_to_multiple(((uint64_t) m_nOTs), REGISTER_BITS), numThreads);
	//cout << "numOTs: " << numOTs << endl;
	m_nBlocks = 0;
	m_lSendLock = new CLock;

	vector<OTSenderThread*> sThreads(numThreads); 

	//uint8_t go;
	//sock.Send(&go, 1);


	for(uint32_t i = 0; i < numThreads; i++)
	{
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}

	for(uint32_t i = 0; i < numThreads; i++)
	{
		sThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(uint32_t i = 0; i < numThreads; i++)
		delete sThreads[i];

#ifdef VERIFY_OT
	uint8_t finished;
	m_nSockets[0].Receive(&finished, 1);

	verifyOT(m_nOTs);
#endif


	return true;
}


//bool OTsender(uint32_t nSndVals, uint32_t nOTs, uint32_t startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, uint8_t* seed)
bool OTExtension1ooNECCSender::OTSenderRoutine(uint32_t id, uint32_t myNumOTs)
{
	CSocket* sock = m_nSockets + id;

	uint32_t nProgress;
	uint32_t myStartPos = id * myNumOTs;
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(myNumOTs, m_nCodeWordBits));
	uint32_t OTsPerIteration = processedOTBlocks * m_nCodeWordBits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos+myNumOTs;

	// The vector with the received bits
	CBitVector vRcv(m_nCodeWordBits * OTsPerIteration);

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for(uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration* AES_BITS);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_BITS << endl;
#endif

	// Contains the parts of the V matrix TOOD: replace OTEXT_BLOCK_SIZE_BITS by processedOTBlocks
	CBitVector Q(m_nCodeWordBits * OTsPerIteration);
	
	// A dummy-buffer
	CBitVector* vSnd;

	// A buffer that holds a counting value, required for a faster uint32_teraction with the AES calls
	uint8_t ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	uint32_t* counter = (uint32_t*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;
	
	nProgress = myStartPos;

#ifdef TIMING
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( nProgress < lim ) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim-nProgress, m_nCodeWordBits));
		OTsPerIteration = processedOTBlocks * m_nCodeWordBits;

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << endl;
#endif

#ifdef TIMING
 		gettimeofday(&tempStart, NULL);
#endif
		//m_lSendLock->Lock();
 		//cout << "(" << id << ") Waiting for " <<  OTsPerIteration * m_nCodeWordBytes << " bytes on OT " << nProgress << endl;
		sock->Receive(vRcv.GetArr(), OTsPerIteration * m_nCodeWordBytes);
		//cout << "(" << id << ") received " <<  OTsPerIteration * m_nCodeWordBytes << " bytes for OT " << nProgress << endl;
		//vRcv.PrintHex(0,1024);
		//m_lSendLock->Unlock();
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, vRcv, processedOTBlocks, ctr_buf);
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(m_nCodeWordBits, OTsPerIteration);
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		MaskInputs(Q, seedbuf, vSnd, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef TIMING
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		nProgress += min(lim-nProgress, OTsPerIteration);
	}

	vRcv.delCBitVector();
	Q.delCBitVector();
	for(uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

#ifdef TIMING
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

	return TRUE;
}

void OTExtension1ooNECCSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t numblocks, uint8_t* ctr_buf)
{
	uint8_t* rcvbufptr = RcvBuf.GetArr();
	uint8_t* Tptr = T.GetArr();
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint64_t tempctr = *counter;
#ifdef AES256_HASH
	intrin_sequential_gen_rnd8(ctr_buf, tempctr, Tptr, (int) 2*numblocks, (int) m_nCodeWordBits, m_vKeySeeds);

	for (uint32_t k = 0; k < m_nCodeWordBits; k++, rcvbufptr += (m_nCodeWordBytes * numblocks))	{
		if(m_nU.GetBit(k)){
			T.XORBytes(rcvbufptr, k*m_nCodeWordBytes * numblocks, m_nCodeWordBytes * numblocks);
		}
	}
#else
	for (uint32_t k = 0; k < m_nCodeWordBits; k++, rcvbufptr += (m_nCodeWordBytes * numblocks))
	{
		*counter = tempctr;
		//one m_nCodeWordBytes / OTEXT_BLOCK_SIZE_uint8_tS = 2, thus 2 times the number of blocks
		for(uint32_t b = 0; b < 2*numblocks; b++, (*counter)++, Tptr += OTEXT_BLOCK_SIZE_BYTES) 	{
			m_cCrypto->encrypt(m_vKeySeeds + k, Tptr, ctr_buf, AES_BYTES);//MPC_AES_ENCRYPT(m_vKeySeeds + k, Tptr, ctr_buf);
		}
		if(m_nU.GetBit(k))
		{
			T.XORBytes(rcvbufptr, k*m_nCodeWordBytes * numblocks, m_nCodeWordBytes * numblocks);
		}
	}
#endif
}

void OTExtension1ooNECCSender::MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs)
{

	//If OT-based PSI is performed, the hashing is skipped and the masking is called directly
	if(m_bProtocol == RN_OT) {
		m_fMaskFct->expandMask(Q, m_nU.GetArr(), ctr, processedOTs, m_nBitLength); //m_sSecParam.statbits
		return;
		//ncrfevals = 1;
	}

	//HASH_CTX sha, shatmp;
	uint8_t hash_buf[m_cCrypto->get_hash_bytes()];
	//SHA_BUFFER sha_buf;

	uint8_t** sbp = new uint8_t*[m_nSndVals];
	CBitVector mask(m_nCodeWordBits);

	uint32_t ncrfevals = m_nSndVals;

#ifdef AES256_HASH
	AES_KEY tk_aeskey;
	block inblock, outblock;
	tk_aeskey.rounds = 14;
#endif

	for(uint32_t u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for(uint32_t i = ctr, j = 0; j<processedOTs; i++, j++)
	{
		//MPC_HASH_INIT(&sha);
		//MPC_HASH_UPDATE(&sha, (uint8_t*) &i, sizeof(i));
		//shatmp = sha;

		for(uint32_t u = 0; u < ncrfevals; u++)
		{
			mask.Copy(m_nU.GetArr(), 0, m_nCodeWordBytes);
			if(m_bProtocol == RN_OT)
				mask.ANDBytes((uint8_t*) m_vCodeWords[m_vValues[1].Get<uint32_t>(i)], 0, m_nCodeWordBytes);
			else
				mask.ANDBytes((uint8_t*) m_vCodeWords[u], 0, m_nCodeWordBytes);

			mask.XORBytes(Q.GetArr() + j * m_nCodeWordBytes, m_nCodeWordBytes);
#ifdef DEBUG_HASH_INPUT
			cout << "hash input for i = " << i << " and u = " << u << ": ";
			mask.PrintHex();
#endif
#ifdef AES256_HASH
			AES_256_Key_Expansion(mask.GetArr(), &tk_aeskey);
			inblock = _mm_loadu_si128((__m128i const*)(hash_buf));
			AES_encryptC(&inblock, &outblock, &tk_aeskey);
			_mm_storeu_si128((__m128i *)(sbp[u]), outblock);
#else
			m_cCrypto->hash_ctr(sbp[u], AES_BYTES, mask.GetArr(), m_nCodeWordBytes, i);
#endif

#ifdef DEBUG_HASH_OUTPUT
			cout << "hash output for i = " << i << " and u = " << u << ": ";
			for(uint32_t j = 0; j < AES_BYTES; j++)
				cout << (hex) << (unsigned int) sbp[u][j];
			cout << (dec) << endl;
#endif
			//memcpy(sbp[u], hash_buf, AES_BYTES);
			sbp[u] += AES_BYTES;
		}
	}

	// Call expandMask to write data uint32_to snd_buf
	cout << "Number of crf evals = "  << ncrfevals << endl;
	for(uint32_t u = 0; u < ncrfevals; u++) {
		m_fMaskFct->expandMask(m_vValues[u], seedbuf[u].GetArr(), ctr, processedOTs, m_nBitLength); //m_sSecParam.statbits
	}

	free(sbp);
}


bool OTExtension1ooNECCSender::verifyOT(uint32_t NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vSnd(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	uint32_t processedOTBlocks, OTsPerIteration, nSnd;
	uint8_t resp;
	for(uint32_t i = 0, offset = 0; i < NumOTs;i+=OTsPerIteration, offset+=ceil_divide(m_nBitLength, 8))
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(NumOTs-i, m_nCodeWordBits));
 		OTsPerIteration = min(processedOTBlocks * m_nCodeWordBits, NumOTs-i);
 		nSnd = ceil_divide(OTsPerIteration * m_nBitLength, 8);
 		//cout << "copying " << nSnd << " bytes from " << CEIL_DIVIDE(i*m_nBitLength, 8) << ", for i = " << i << endl;
 		for(uint32_t u = 0; u < m_nSndVals; u++) {
			vSnd.Copy(m_vValues[u].GetArr() + offset, 0, nSnd);
			sock.Send(vSnd.GetArr(), nSnd);
 		}
		sock.Receive(&resp, 1);
		if(resp == 0x00)
		{
			cout << "OT verification unsuccessful" << endl;
			return false;
		}
	}
	vSnd.delCBitVector();
	cout << "OT Verification successful" << endl;
	return true;
}


