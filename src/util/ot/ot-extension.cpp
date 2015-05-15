#include "ot-extension.h"




BOOL OTExtensionReceiver::receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type, int numThreads, MaskingFunction* unmaskfct)
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
BOOL OTExtensionReceiver::receive(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int internal_numOTs = CEIL_DIVIDE(PadToRegisterSize(m_nOTs), numThreads);

	//BYTE go;
	//Wait for the signal of the corresponding sender thread
	//sock.Receive(&go, 1);

	//Create temporary result buf to which the threads write their temporary masks
	m_vTempOTMasks.Create(internal_numOTs * numThreads * m_nBitLength);

	vector<OTReceiverThread*> rThreads(numThreads); 
	for(int i = 0; i < numThreads; i++)
	{
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}
	
	if(m_bProtocol != R_OT && m_bProtocol != OCRS_OT)
	{
		ReceiveAndProcess(numThreads);
	}

	for(int i = 0; i < numThreads; i++)
	{
		rThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(int i = 0; i < numThreads; i++)
		delete rThreads[i];

	if(m_bProtocol == R_OT || m_bProtocol == OCRS_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, CEIL_DIVIDE(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}


#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	BYTE finished = 0x01;
	m_nSockets[0].Send(&finished, 1);

	verifyOT(m_nOTs);
#endif


	return true;
}



BOOL OTExtensionReceiver::OTReceiverRoutine(int id, int myNumOTs)
{
	//cout << "Thread " << id << " started" << endl;
	int myStartPos = id * myNumOTs;
	int i = myStartPos, nProgress = myStartPos;
	int RoundWindow = 2;
	int roundctr = 0;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	int OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
	int OTwindow = NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*RoundWindow;
	CSocket sock = m_nSockets[id];

	//counter variables
	int numblocks = CEIL_DIVIDE(myNumOTs, OTsPerIteration);
	int nSize;

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
	CBitVector seedbuf(OTwindow*AES_KEY_BITS);// = new CBitVector[RoundWindow];
	//for(int j = 0; j < RoundWindow; j++)
	//	seedbuf[j].Create(OTwindow * AES_KEY_BITS);



	BYTE ctr_buf[AES_BYTES] = {0};
	int* counter = (int*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( i < lim )
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-i, OTEXT_BLOCK_SIZE_BITS));
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



void OTExtensionReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf)
{
	int* counter = (int*) ctr_buf;
	int tempctr = (*counter);

	BYTE* Tptr = T.GetArr();
	BYTE* sndbufptr = SndBuf.GetArr();
	int ctrbyte = ctr/8;
	for(int k = 0; k < m_nSymSecParam; k++)
	{
		(*counter) = tempctr;
		for(int b = 0; b < numblocks; b++, (*counter)++)
		{
			MPC_AES_ENCRYPT(m_vKeySeedMtx + 2*k, Tptr, ctr_buf);
			Tptr+=OTEXT_BLOCK_SIZE_BYTES;

			MPC_AES_ENCRYPT(m_vKeySeedMtx + (2*k) + 1, sndbufptr, ctr_buf);
			sndbufptr+=OTEXT_BLOCK_SIZE_BYTES;
		}
		SndBuf.XORBytesReverse(m_nChoices.GetArr()+ctrbyte, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
	}
	SndBuf.XORBytes(T.GetArr(), 0, OTEXT_BLOCK_SIZE_BYTES*numblocks*m_nSymSecParam);
}



void OTExtensionReceiver::HashValues(CBitVector& T, CBitVector& seedbuf, int ctr, int processedOTs)
{
	BYTE* Tptr = T.GetArr();
	BYTE* bufptr = seedbuf.GetArr();//m_vSeedbuf.GetArr() + ctr * AES_KEY_BYTES;//seedbuf.GetArr();

	HASH_CTX sha;
	BYTE hash_buf[SHA1_BYTES];

	for(int i = ctr; i < ctr+processedOTs; i++, Tptr+=OTEXT_BLOCK_SIZE_BYTES, bufptr+=AES_KEY_BYTES)
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
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));
			//OTEXT_HASH_UPDATE(&sha, (BYTE*) &hash_ctr, sizeof(hash_ctr));
		MPC_HASH_UPDATE(&sha, Tptr, m_nSymSecParam>>3);
		MPC_HASH_FINAL(&sha, hash_buf);
		//}
		memcpy(bufptr, hash_buf, AES_KEY_BYTES);
#endif


		//m_nRet.SetBits(hash_buf, i * m_nBitLength, m_nBitLength);
	}

	//
	m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength);
}


//void OTExtensionReceiver::ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, int id, int ctr, int processedOTs)
void OTExtensionReceiver::ReceiveAndProcess(int numThreads)
{
	int progress = 0;
	int threadOTs = CEIL_DIVIDE(PadToRegisterSize(m_nOTs), numThreads);
	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(threadOTs, OTEXT_BLOCK_SIZE_BITS));
	int OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
	int processedOTs;
	int OTid;
	int rcvbytes;
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


		m_nSockets[0].Receive((BYTE*) &OTid, sizeof(int));
		//cout << "Processing blockid " << OTid;
		m_nSockets[0].Receive((BYTE*) &processedOTs, sizeof(int));
		//cout << " with " << processedOTs << " OTs ";
		rcvbytes = CEIL_DIVIDE(processedOTs * m_nBitLength, 8);
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

BOOL OTExtensionReceiver::verifyOT(int NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vRcvX0(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector* Xc;
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	BYTE* tempXc = new BYTE[bytelen];
	BYTE* tempRet = new BYTE[bytelen];
	BYTE resp;
	for(int i = 0; i < NumOTs;)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, OTEXT_BLOCK_SIZE_BITS));
 		//OTsPerIteration = processedOTBlocks * Z_REGISTER_BITS;
		OTsPerIteration = min(processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
		sock.Receive(vRcvX0.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		sock.Receive(vRcvX1.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		for(int j = 0; j < OTsPerIteration && i < NumOTs; j++, i++)
		{
			if(m_nChoices.GetBitNoMask(i) == 0) Xc = &vRcvX0;
			else Xc = &vRcvX1;

			Xc->GetBits(tempXc, j*m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i*m_nBitLength, m_nBitLength);
			for(int k = 0; k < bytelen; k++)
			{
				if(tempXc[k] != tempRet[k])
				{
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (unsigned int) m_nChoices.GetBitNoMask(i)
							<< " = " << (unsigned int) tempXc[k] << " and res = " << (unsigned int) tempRet[k] << (dec) << endl;
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



BOOL OTExtensionSender::send(int numOTs, int bitlength, CBitVector& x0, CBitVector& x1, BYTE type,
		int numThreads, MaskingFunction* maskfct)
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
BOOL OTExtensionSender::send(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int numOTs = CEIL_DIVIDE(PadToRegisterSize(m_nOTs), numThreads);
	m_nBlocks = 0;
	m_lSendLock = new CLock;


	vector<OTSenderThread*> sThreads(numThreads); 

	//BYTE go;
	//sock.Send(&go, 1);

	for(int i = 0; i < numThreads; i++)
	{
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}
	
	if(m_bProtocol != R_OT && m_bProtocol != OCRS_OT)
	{
		SendBlocks(numThreads);
	}

	for(int i = 0; i < numThreads; i++)
	{
		sThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(int i = 0; i < numThreads; i++)
		delete sThreads[i];

#ifdef VERIFY_OT
	BYTE finished;
	m_nSockets[0].Receive(&finished, 1);

	verifyOT(m_nOTs);
#endif

/*	cout << "OT0 val= ";
	m_vValues[0].PrintBinary();
	cout << "OT1 val= ";
	m_vValues[1].PrintBinary();*/

	return true;
}


//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL OTExtensionSender::OTSenderRoutine(int id, int myNumOTs)
{
	CSocket sock = m_nSockets[id];

	int nProgress;
	int myStartPos = id * myNumOTs; 
	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	int OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	//TODO: Check if this works:
	if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
		m_nSndVals = 1;

	// The vector with the received bits
	CBitVector vRcv(m_nSymSecParam * OTsPerIteration);
		
	// Holds the reply that is sent back to the receiver
	int numsndvals = 2;
	CBitVector* vSnd;

	/*if(m_bProtocol == G_OT) numsndvals = 2;
	else if (m_bProtocol == C_OT || m_bProtocol == S_OT) numsndvals = 1;
	else numsndvals = 0;*/

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for(int u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration* AES_KEY_BITS);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];//(CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for(int i = 0; i < numsndvals; i++)
	{
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix TOOD: replace OTEXT_BLOCK_SIZE_BITS by processedOTBlocks
	CBitVector Q(OTEXT_BLOCK_SIZE_BITS * OTsPerIteration);
	
	// A buffer that holds a counting value, required for a faster interaction with the AES calls
	BYTE ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	int* counter = (int*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;
	
	nProgress = myStartPos;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( nProgress < lim ) //do while there are still transfers missing
	{

		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-nProgress, OTEXT_BLOCK_SIZE_BITS));
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
	for(int u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for(int i = 0; i < numsndvals; i++)
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

void OTExtensionSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int numblocks, BYTE* ctr_buf)
{
	BYTE* rcvbufptr = RcvBuf.GetArr();
	BYTE* Tptr = T.GetArr();
	int dummy;
	int* counter = (int*) ctr_buf;
	int tempctr = *counter;
	for (int k = 0; k < m_nSymSecParam; k++, rcvbufptr += (OTEXT_BLOCK_SIZE_BYTES * numblocks))
	{
		*counter = tempctr;
		for(int b = 0; b < numblocks; b++, (*counter)++, Tptr += OTEXT_BLOCK_SIZE_BYTES)
		{
			MPC_AES_ENCRYPT(m_vKeySeeds + k, Tptr, ctr_buf);
		}
		if(m_nU.GetBit(k))
		{
			T.XORBytes(rcvbufptr, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
		}
	}
}

void OTExtensionSender::MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, int ctr, int processedOTs)
{
	int numhashiters = CEIL_DIVIDE(m_nBitLength, SHA1_BITS);
	HASH_CTX sha, shatmp;

	BYTE hash_buf[SHA1_BYTES];
	//SHA_BUFFER sha_buf;
	BYTE* Qptr = Q.GetArr();

	BYTE** sbp = new BYTE*[m_nSndVals];

	for(int u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for(int i = ctr, j = 0; j<processedOTs; i++, j++)
	{
		if(m_bProtocol == OCRS_OT && m_vValues[0].GetBitNoMask(i) == 0)
		{
			continue;
		}

#ifndef FIXED_KEY_AES_HASHING
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));
		shatmp = sha;
#endif
		for(int u = 0; u < m_nSndVals; u++)
		{
			//omit zero possibility
			//if( || m_bProtocol == OCRS_OT)
			//	Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);


			if(u == 1 || m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
				Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);

#ifdef FIXED_KEY_AES_HASHING
			//AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, int id, int bytessecparam
			FixedKeyHashing(m_kCRFKey, sbp[u], Q.GetArr() + j * OTEXT_BLOCK_SIZE_BYTES, hash_buf, i, m_nSymSecParam>>3);
#else
			sha = shatmp;
			MPC_HASH_UPDATE(&sha, Q.GetArr()+j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);
			MPC_HASH_FINAL(&sha, hash_buf);

			memcpy(sbp[u], hash_buf, AES_KEY_BYTES);
#endif

			//cout << ((unsigned int) sbp[u][0] & 0x01);
			sbp[u] += AES_KEY_BYTES;

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
	for(int u = 0; u < m_nSndVals; u++)
		m_fMaskFct->expandMask(snd_buf[u], seedbuf[u].GetArr(), 0, processedOTs, m_nBitLength);
}

void OTExtensionSender::ProcessAndEnqueue(CBitVector* snd_buf, int id, int progress, int processedOTs)
{
	//cout << "processed OTs: " << processedOTs << endl;
	m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf, m_bProtocol);

	if(m_bProtocol == R_OT)
		return;

	OTBlock* block = new OTBlock;
	int bufsize = CEIL_DIVIDE(processedOTs * m_nBitLength, 8);

	block->blockid = progress;
	block->processedOTs = processedOTs;


	if(m_bProtocol == G_OT)
	{
		block->snd_buf = new BYTE[bufsize<<1];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
		memcpy(block->snd_buf+bufsize, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == C_OT)
	{
		block->snd_buf = new BYTE[bufsize];
		memcpy(block->snd_buf, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == S_OT)
	{
		block->snd_buf = new BYTE[bufsize];
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


void OTExtensionSender::SendBlocks(int numThreads)
{
	int progress = 0;
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
				m_nSockets[0].Send((BYTE*) &(tempBlock->blockid), sizeof(int));
				m_nSockets[0].Send((BYTE*) &(tempBlock->processedOTs), sizeof(int));
				m_nSockets[0].Send(tempBlock->snd_buf, 2*CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == C_OT)
			{
				m_nSockets[0].Send((BYTE*) &(tempBlock->blockid), sizeof(int));
				m_nSockets[0].Send((BYTE*) &(tempBlock->processedOTs), sizeof(int));
				m_nSockets[0].Send(tempBlock->snd_buf, CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == S_OT)
			{
				m_nSockets[0].Send((BYTE*) &(tempBlock->blockid), sizeof(int));
				m_nSockets[0].Send((BYTE*) &(tempBlock->processedOTs), sizeof(int));
				m_nSockets[0].Send(tempBlock->snd_buf, CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
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



BOOL OTExtensionSender::verifyOT(int NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vSnd(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	int nSnd;
	BYTE resp;
	for(int i = 0; i < NumOTs;i+=OTsPerIteration)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, OTEXT_BLOCK_SIZE_BITS));
 		OTsPerIteration = min(processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
 		nSnd = CEIL_DIVIDE(OTsPerIteration * m_nBitLength, 8);
 		//cout << "copying " << nSnd << " bytes from " << CEIL_DIVIDE(i*m_nBitLength, 8) << ", for i = " << i << endl;
 		vSnd.Copy(m_vValues[0].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
 		vSnd.Copy(m_vValues[1].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
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


