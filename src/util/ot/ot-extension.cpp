#include "ot-extension.h"


bool OTExtensionReceiver::receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret,
	uint8_t type, uint32_t numThreads, MaskingFunction* unmaskfct)
{
		m_nOTs = numOTs;
		m_nBitLength = bitlength;
		m_nChoices = choices;
		m_nRet = ret;
		m_bProtocol = type;
		m_fMaskFct = unmaskfct;
		return receive(numThreads);
};

//Initialize and start numThreads OTSenderThread
bool OTExtensionReceiver::receive(uint32_t numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t internal_numOTs = ceil_divide(pad_to_multiple(m_nOTs, REGISTER_BITS), numThreads);

	//uint8_t go;
	//Wait for the signal of the corresponding sender thread
	//sock.Receive(&go, 1);

	//Create temporary result buf to which the threads write their temporary masks
	m_vTempOTMasks.Create(internal_numOTs * numThreads * m_nBitLength);

	vector<OTReceiverThread*> rThreads(numThreads); 
	for(uint32_t i = 0; i < numThreads; i++)
	{
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}
	
	if(m_bProtocol != R_OT && m_bProtocol != OCRS_OT)
	{
		ReceiveAndProcess(numThreads);
	}

	for(uint32_t i = 0; i < numThreads; i++)
	{
		rThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(uint32_t i = 0; i < numThreads; i++)
		delete rThreads[i];

	if(m_bProtocol == R_OT || m_bProtocol == OCRS_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, ceil_divide(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}


#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	uint8_t finished = 0x01;
	m_nSockets[0].Send(&finished, 1);

	verifyOT(m_nOTs);
#endif


	return true;
}



bool OTExtensionReceiver::OTReceiverRoutine(uint32_t id, uint32_t myNumOTs)
{
	//cout << "Thread " << id << " started" << endl;
	uint32_t myStartPos = id * myNumOTs;
	uint32_t i = myStartPos, nProgress = myStartPos;
	uint32_t RoundWindow = 2;
	uint32_t roundctr = 0;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos+myNumOTs;

	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	uint32_t OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
	uint32_t OTwindow = NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*RoundWindow;
	CSocket sock = m_nSockets[id];

	//counter variables
	uint32_t numblocks = ceil_divide(myNumOTs, OTsPerIteration);
	uint32_t nSize;

	// The receive buffer
	CBitVector vRcv;
	if(m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if(m_bProtocol == C_OT || m_bProtocol == S_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);

	// A temporary part of the T matrix
	CBitVector T(OTEXT_BLOCK_SIZE_BITS * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nSymSecParam * OTsPerIteration);

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow*m_cCrypto->get_aes_key_bytes() * 8);// = new CBitVector[RoundWindow];
	//for(uint32_t j = 0; j < RoundWindow; j++)
	//	seedbuf[j].Create(OTwindow * AES_KEY_BITS);



	uint8_t ctr_buf[AES_BYTES] = {0};
	uint32_t* counter = (uint32_t*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( i < lim )
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim-i, OTEXT_BLOCK_SIZE_BITS));
 		OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
		nSize = (m_nSymSecParam>>3) * OTsPerIteration;

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i, ctr_buf);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		T.EklundhBitTranspose(OTEXT_BLOCK_SIZE_BITS, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		//cout << "offset: " << (AES_KEY_BYTES * (i-nProgress))<< ", i = " << i << ", nprogress = " << nProgress << ", otwindow = " << OTwindow << endl;
		HashValues(T, seedbuf, i, min(lim-i, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif

 		//cout << "Sending " << nSize << " Bytes " << endl;
 		sock.Send( vSnd.GetArr(), nSize );
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		i+=min(lim-i, OTsPerIteration);

#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
#endif
 		vSnd.Reset();
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	vRcv.delCBitVector();
	seedbuf.delCBitVector();

#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif
#ifndef BATCH
	cout << "Receiver finished successfully" << endl;
#endif
	//sleep(1);
	return TRUE;
}



void OTExtensionReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, uint8_t* ctr_buf)
{
	uint32_t* counter = (uint32_t*) ctr_buf;
	uint32_t tempctr = (*counter);

	uint8_t* Tptr = T.GetArr();
	uint8_t* sndbufptr = SndBuf.GetArr();
	uint32_t ctrbyte = ctr/8;
#ifdef AES256_HASH
	cerr << "Not supported with AES256 HASH enabled. Exiting." << endl;
	exit(0);
#else
	for(uint32_t k = 0; k < m_nSymSecParam; k++)
	{
		(*counter) = tempctr;
		for(uint32_t b = 0; b < numblocks; b++, (*counter)++)
		{
			//MPC_AES_ENCRYPT(m_vKeySeedMtx + 2*k, Tptr, ctr_buf);
			m_cCrypto->encrypt(m_vKeySeedMtx + 2*k, Tptr, ctr_buf, AES_BYTES);
			Tptr+=OTEXT_BLOCK_SIZE_BYTES;

			//MPC_AES_ENCRYPT(m_vKeySeedMtx + (2*k) + 1, sndbufptr, ctr_buf);
			m_cCrypto->encrypt(m_vKeySeedMtx + (2*k) + 1, sndbufptr, ctr_buf, AES_BYTES);
			sndbufptr+=OTEXT_BLOCK_SIZE_BYTES;
		}
		SndBuf.XORBytesReverse(m_nChoices.GetArr()+ctrbyte, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
	}
#endif
	SndBuf.XORBytes(T.GetArr(), (uint32_t) 0, OTEXT_BLOCK_SIZE_BYTES*numblocks*m_nSymSecParam);
}



void OTExtensionReceiver::HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t processedOTs)
{
	uint8_t* Tptr = T.GetArr();
	uint8_t* bufptr = seedbuf.GetArr();//m_vSeedbuf.GetArr() + ctr * AES_KEY_BYTES;//seedbuf.GetArr();

	//HASH_CTX sha;
	uint32_t hashbytes = m_cCrypto->get_hash_bytes();
	uint32_t hashinbytelen = (m_nSymSecParam>>3) + sizeof(uint32_t);
	uint32_t aes_key_bytes = m_cCrypto->get_aes_key_bytes();

	uint8_t hash_buf[hashbytes];

	uint8_t* inbuf = (uint8_t*) malloc(hashinbytelen);

	for(uint32_t i = ctr; i < ctr+processedOTs; i++, Tptr+=OTEXT_BLOCK_SIZE_BYTES, bufptr+=aes_key_bytes)
	{
		if((m_bProtocol == S_OT || m_bProtocol == OCRS_OT) && m_nChoices.GetBitNoMask(i) == 0)
		{
			continue;
		}

		//for(hash_ctr = 0; hash_ctr < numhashiters; hash_ctr++, sha_buf.data+=SHA1_BYTES)
		//{
#ifdef FIXED_KEY_AES_HASHING
		FixedKeyHashing(m_kCRFKey, bufptr, Tptr, hash_buf, i, m_nSymSecParam>>3);
#else
		//MPC_HASH_INIT(&sha);
		//MPC_HASH_UPDATE(&sha, (uint8_t*) &i, sizeof(i));
			//OTEXT_HASH_UPDATE(&sha, (uint8_t*) &hash_ctr, sizeof(hash_ctr));
		//MPC_HASH_UPDATE(&sha, Tptr, m_nSymSecParam>>3);
		//MPC_HASH_FINAL(&sha, hash_buf);
		//}
		cout << "Hashing here" << endl;
		memcpy(inbuf, &i, sizeof(uint32_t));
		memcpy(inbuf+sizeof(uint32_t), Tptr, m_nSymSecParam>>3);
		m_cCrypto->hash(hash_buf, aes_key_bytes, inbuf, hashinbytelen);

		memcpy(bufptr, hash_buf, aes_key_bytes);
#endif


		//m_nRet.SetBits(hash_buf, i * m_nBitLength, m_nBitLength);
	}

	//
	m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength);
}


//void OTExtensionReceiver::ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, uint32_t id, uint32_t ctr, uint32_t processedOTs)
void OTExtensionReceiver::ReceiveAndProcess(uint32_t numThreads)
{
	uint32_t progress = 0;
	uint32_t threadOTs = ceil_divide(pad_to_multiple(m_nOTs, REGISTER_BITS), numThreads);
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(threadOTs, OTEXT_BLOCK_SIZE_BITS));
	uint32_t OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
	uint32_t processedOTs;
	uint32_t OTid;
	uint32_t rcvbytes;
	CBitVector vRcv;

#ifdef OTTiming
	double totalRcvTime = 0;
	timeval tempStart, tempEnd;
#endif

	if(m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if(m_bProtocol == C_OT || m_bProtocol == S_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);

	while(progress < m_nOTs)
	{
		//cout << "Waiting for block " << endl;


		m_nSockets[0].Receive((uint8_t*) &OTid, sizeof(uint32_t));
		//cout << "Processing blockid " << OTid;
		m_nSockets[0].Receive((uint8_t*) &processedOTs, sizeof(uint32_t));
		//cout << " with " << processedOTs << " OTs ";
		rcvbytes = ceil_divide(processedOTs * m_nBitLength, 8);
		if(m_bProtocol == G_OT)
			rcvbytes = rcvbytes*m_nSndVals;
		//cout << "Receiving " << rcvbytes << " bytes" << endl;
		rcvbytes = m_nSockets[0].Receive(vRcv.GetArr(), rcvbytes);

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
 		//cout << "unmask" << endl;
		m_fMaskFct->UnMask(OTid, processedOTs, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_bProtocol);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
#endif
 		progress += processedOTs;
	}

#ifdef OTTiming
	cout << "Total time spent processing received data: " << totalRcvTime << endl;
#endif

	vRcv.delCBitVector();
}

bool OTExtensionReceiver::verifyOT(uint32_t NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vRcvX0(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector* Xc;
	uint32_t processedOTBlocks, OTsPerIteration;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint8_t* tempXc = new uint8_t[bytelen];
	uint8_t* tempRet = new uint8_t[bytelen];
	uint8_t resp;
	for(uint32_t i = 0; i < NumOTs;)
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(NumOTs-i, (uint32_t) OTEXT_BLOCK_SIZE_BITS));
 		//OTsPerIteration = processedOTBlocks * Z_REGISTER_BITS;
		OTsPerIteration = min((uint32_t)processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
		sock.Receive(vRcvX0.GetArr(), ceil_divide(m_nBitLength * OTsPerIteration, 8));
		sock.Receive(vRcvX1.GetArr(), ceil_divide(m_nBitLength * OTsPerIteration, 8));
		for(uint32_t j = 0; j < OTsPerIteration && i < NumOTs; j++, i++)
		{
			if(m_nChoices.GetBitNoMask(i) == 0) Xc = &vRcvX0;
			else Xc = &vRcvX1;

			Xc->GetBits(tempXc, j*m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i*m_nBitLength, m_nBitLength);
			for(uint32_t k = 0; k < bytelen; k++)
			{
				if(tempXc[k] != tempRet[k])
				{
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (uint32_t) m_nChoices.GetBitNoMask(i)
							<< " = " << (uint32_t) tempXc[k] << " and res = " << (uint32_t) tempRet[k] << (dec) << endl;
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

	vRcvX0.delCBitVector();
	vRcvX1.delCBitVector();

	cout << "OT Verification successful" << endl;
	return true;
}



bool OTExtensionSender::send(uint32_t numOTs, uint32_t bitlength, CBitVector& x0, CBitVector& x1, uint8_t type,
		uint32_t numThreads, MaskingFunction* maskfct)
{
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues[0] = x0;
	m_vValues[1] = x1;
	m_bProtocol = type;
	m_fMaskFct = maskfct;
	return send(numThreads);
}


//Initialize and start numThreads OTSenderThread
bool OTExtensionSender::send(uint32_t numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t numOTs = ceil_divide(pad_to_multiple(m_nOTs, REGISTER_BITS), numThreads);
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
	
	if(m_bProtocol != R_OT && m_bProtocol != OCRS_OT)
	{
		SendBlocks(numThreads);
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

/*	cout << "OT0 val= ";
	m_vValues[0].PrintBinary();
	cout << "OT1 val= ";
	m_vValues[1].PrintBinary();*/

	return true;
}


//BOOL OTsender(uint32_t nSndVals, uint32_t nOTs, uint32_t startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, uint8_t* seed)
bool OTExtensionSender::OTSenderRoutine(uint32_t id, uint32_t myNumOTs)
{
	CSocket sock = m_nSockets[id];

	uint32_t nProgress;
	uint32_t myStartPos = id * myNumOTs;
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, (uint32_t) ceil_divide(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	uint32_t OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos+myNumOTs;

	//TODO: Check if this works:
	if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
		m_nSndVals = 1;

	// The vector with the received bits
	CBitVector vRcv(m_nSymSecParam * OTsPerIteration);
		
	// Holds the reply that is sent back to the receiver
	uint32_t numsndvals = 2;
	CBitVector* vSnd;

	/*if(m_bProtocol == G_OT) numsndvals = 2;
	else if (m_bProtocol == C_OT || m_bProtocol == S_OT) numsndvals = 1;
	else numsndvals = 0;*/

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for(uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration* m_cCrypto->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];//(CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for(uint32_t i = 0; i < numsndvals; i++)
	{
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix TOOD: replace OTEXT_BLOCK_SIZE_BITS by processedOTBlocks
	CBitVector Q(OTEXT_BLOCK_SIZE_BITS * OTsPerIteration);
	
	// A buffer that holds a counting value, required for a faster interaction with the AES calls
	uint8_t ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	uint32_t* counter = (uint32_t*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;
	
	nProgress = myStartPos;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( nProgress < lim ) //do while there are still transfers missing
	{

		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim-nProgress, OTEXT_BLOCK_SIZE_BITS));
		OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << endl;
#endif

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
 		//cout << "Waiting for data" << endl;
		sock.Receive(vRcv.GetArr(), m_nSymSecParam*OTEXT_BLOCK_SIZE_BYTES * processedOTBlocks);
	//	cout << "received data" << endl;
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, vRcv, processedOTBlocks, ctr_buf);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(OTEXT_BLOCK_SIZE_BITS, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		MaskInputs(Q, seedbuf, vSnd, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		ProcessAndEnqueue(vSnd, id, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		nProgress += min(lim-nProgress, OTsPerIteration);
	}

	vRcv.delCBitVector();
	Q.delCBitVector();
	for(uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for(uint32_t i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if(numsndvals > 0)	free(vSnd);

#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

#ifndef BATCH
	cout << "Sender finished successfully" << endl;
#endif
	return TRUE;
}

void OTExtensionSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t numblocks, uint8_t* ctr_buf)
{
	uint8_t* rcvbufptr = RcvBuf.GetArr();
	uint8_t* Tptr = T.GetArr();
	uint32_t dummy;
	uint32_t* counter = (uint32_t*) ctr_buf;
	uint32_t tempctr = *counter;
#ifdef AES256_HASH
	cerr << "Not supported with AES256 HASH enabled. Exiting." << endl;
	exit(0);
#else
	for (uint32_t k = 0; k < m_nSymSecParam; k++, rcvbufptr += (OTEXT_BLOCK_SIZE_BYTES * numblocks))
	{
		*counter = tempctr;
		for(uint32_t b = 0; b < numblocks; b++, (*counter)++, Tptr += OTEXT_BLOCK_SIZE_BYTES)
		{
			//MPC_AES_ENCRYPT(m_vKeySeeds + k, Tptr, ctr_buf);
			m_cCrypto->encrypt(m_vKeySeeds + k, Tptr, ctr_buf, AES_BYTES);
		}
		if(m_nU.GetBit(k))
		{
			T.XORBytes(rcvbufptr, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
		}
	}
#endif
}

void OTExtensionSender::MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs)
{
	uint32_t hashbytes = m_cCrypto->get_hash_bytes();

	uint32_t numhashiters = ceil_divide(m_nBitLength, hashbytes*8);
	//HASH_CTX sha, shatmp;

	uint8_t hash_buf[hashbytes];
	//SHA_BUFFER sha_buf;
	uint8_t* Qptr = Q.GetArr();
	uint32_t hashinbytelen = (m_nSymSecParam>>3) + sizeof(uint32_t);

	uint8_t** sbp = new uint8_t*[m_nSndVals];
	uint8_t* inbuf = (uint8_t*) malloc(hashinbytelen);
	uint32_t aes_key_bytes = m_cCrypto->get_aes_key_bytes();

	for(uint32_t u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for(uint32_t i = ctr, j = 0; j<processedOTs; i++, j++)
	{
		if(m_bProtocol == OCRS_OT && m_vValues[0].GetBitNoMask(i) == 0)
		{
			continue;
		}

#ifndef FIXED_KEY_AES_HASHING
		//MPC_HASH_INIT(&sha);
		//MPC_HASH_UPDATE(&sha, (uint8_t*) &i, sizeof(i));
		//shatmp = sha;
#endif
		for(uint32_t u = 0; u < m_nSndVals; u++)
		{
			//omit zero possibility
			//if( || m_bProtocol == OCRS_OT)
			//	Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);


			if(u == 1 || m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
				Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);

#ifdef FIXED_KEY_AES_HASHING
			//AES_KEY_CTX* aeskey, uint8_t* outbuf, uint8_t* inbuf, uint8_t* tmpbuf, uint32_t id, uint32_t bytessecparam
			FixedKeyHashing(m_kCRFKey, sbp[u], Q.GetArr() + j * OTEXT_BLOCK_SIZE_BYTES, hash_buf, i, m_nSymSecParam>>3);
#else
			//sha = shatmp;
			//MPC_HASH_UPDATE(&sha, Q.GetArr()+j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);
			//MPC_HASH_FINAL(&sha, hash_buf);
			memcpy(inbuf, &i, sizeof(uint32_t));
			memcpy(inbuf+sizeof(uint32_t), Q.GetArr() + j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);
			m_cCrypto->hash(hash_buf, aes_key_bytes, inbuf, hashinbytelen);
			//memcpy(sbp[u], resbuf, aes_key_bytes);


			memcpy(sbp[u], hash_buf, aes_key_bytes);
#endif

			//cout << ((unsigned uint32_t) sbp[u][0] & 0x01);
			sbp[u] += aes_key_bytes;

			if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
			{
				u=m_nSndVals-1;
			}
		}
	}

	if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
	{
		m_fMaskFct->expandMask(snd_buf[0], seedbuf[0].GetArr(), 0, processedOTs, m_nBitLength);
		return;
	}

	//Two calls to expandMask, both writing into snd_buf
	for(uint32_t u = 0; u < m_nSndVals; u++)
		m_fMaskFct->expandMask(snd_buf[u], seedbuf[u].GetArr(), 0, processedOTs, m_nBitLength);

	free(inbuf);
}

void OTExtensionSender::ProcessAndEnqueue(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs)
{
	//cout << "processed OTs: " << processedOTs << endl;
	m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf, m_bProtocol);

	if(m_bProtocol == R_OT)
		return;

	OTBlock* block = new OTBlock;
	uint32_t bufsize = ceil_divide(processedOTs * m_nBitLength, 8);

	block->blockid = progress;
	block->processedOTs = processedOTs;


	if(m_bProtocol == G_OT)
	{
		block->snd_buf = new uint8_t[bufsize<<1];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
		memcpy(block->snd_buf+bufsize, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == C_OT)
	{
		block->snd_buf = new uint8_t[bufsize];
		memcpy(block->snd_buf, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == S_OT)
	{
		block->snd_buf = new uint8_t[bufsize];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
	}


	m_lSendLock->Lock();
	//Lock this part if multiple threads are used!
	if(m_nBlocks == 0)
	{
		m_sBlockHead = block;
		m_sBlockTail = block;
	} else {
		m_sBlockTail->next = block;
		m_sBlockTail = block;
	}
	m_nBlocks++;
	m_lSendLock->Unlock();
}


void OTExtensionSender::SendBlocks(uint32_t numThreads)
{
	uint32_t progress = 0;
	OTBlock* tempBlock;

#ifdef OTTiming
	double totalTnsTime = 0;
	timeval tempStart, tempEnd;
#endif

	while(progress < m_nOTs)
	{
		if(m_nBlocks > 0)
		{
#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
			tempBlock = m_sBlockHead;
			if(m_bProtocol == G_OT)
			{
				m_nSockets[0].Send((uint8_t*) &(tempBlock->blockid), sizeof(uint32_t));
				m_nSockets[0].Send((uint8_t*) &(tempBlock->processedOTs), sizeof(uint32_t));
				m_nSockets[0].Send(tempBlock->snd_buf, 2*ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == C_OT)
			{
				m_nSockets[0].Send((uint8_t*) &(tempBlock->blockid), sizeof(uint32_t));
				m_nSockets[0].Send((uint8_t*) &(tempBlock->processedOTs), sizeof(uint32_t));
				m_nSockets[0].Send(tempBlock->snd_buf, ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == S_OT)
			{
				m_nSockets[0].Send((uint8_t*) &(tempBlock->blockid), sizeof(uint32_t));
				m_nSockets[0].Send((uint8_t*) &(tempBlock->processedOTs), sizeof(uint32_t));
				m_nSockets[0].Send(tempBlock->snd_buf, ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			//Lock this part
			m_sBlockHead = m_sBlockHead->next;

			m_lSendLock->Lock();
			m_nBlocks--;
			m_lSendLock->Unlock();

			progress += tempBlock->processedOTs;

			delete tempBlock->snd_buf;
			delete tempBlock;

#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
#endif
		}
	}
#ifdef OTTiming
	cout << "Total time spent transmitting data: " << totalTnsTime << endl;
#endif
}



bool OTExtensionSender::verifyOT(uint32_t NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vSnd(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	uint32_t processedOTBlocks, OTsPerIteration;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint32_t nSnd;
	uint8_t resp;
	for(uint32_t i = 0; i < NumOTs;i+=OTsPerIteration)
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(NumOTs-i, OTEXT_BLOCK_SIZE_BITS));
 		OTsPerIteration = min(processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
 		nSnd = ceil_divide(OTsPerIteration * m_nBitLength, 8);
 		//cout << "copying " << nSnd << " bytes from " << ceil_divide(i*m_nBitLength, 8) << ", for i = " << i << endl;
 		vSnd.Copy(m_vValues[0].GetArr() + ceil_divide(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
 		vSnd.Copy(m_vValues[1].GetArr() + ceil_divide(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
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


