/*
 * typedefs.h
 *
 *  Created on: Jul 1, 2014
 *      Author: mzohner
 */

#ifndef TYPEDEFS_H_
#define TYPEDEFS_H_

//#define DEBUG
//#define BATCH
//#define TIMING
//#define AES256_HASH
//#define USE_PIPELINED_AES_NI

#include <iostream>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <stdint.h>


using namespace std;


enum field_type {P_FIELD, ECC_FIELD};
enum role_type {SERVER, CLIENT};

#define MAX_REPLY_BITS			65536 //at most 2^16 bits may be sent in one go
#define ELEMENT_WINDOW 1024
#define MAX_REPLY_BYTES			MAX_REPLY_BITS/8

#define RETRY_CONNECT		1000
#define CONNECT_TIMEO_MILISEC	10000


#define OTEXT_BLOCK_SIZE_BITS	128
#define OTEXT_BLOCK_SIZE_BYTES	16

#define NUMOTBLOCKS 1024
#define REGISTER_BITS AES_BITS
#define REGISTER_BYTES AES_BYTES

#define VECTOR_INTERNAL_SIZE 8

#define MAX_INT (~0)
#if (MAX_INT == 0xFFFFFFFF)
#define MACHINE_SIZE_32
typedef uint32_t REGISTER_SIZE;

#elif (MAX_INT == 0xFFFFFFFFFFFFFFFF)
#define MACHINE_SIZE_64
typedef unsigned long int REGISTER_SIZE;

#else
#define MACHINE_SIZE_16
typedef uint16_t REGISTER_SIZE;

#endif

#define LOG2_REGISTER_SIZE		ceil_log2(sizeof(REGISTER_SIZE) << 3)

#ifdef WIN32
#include <WinSock2.h>
#include <windows.h>

typedef unsigned short	USHORT;
typedef int socklen_t;
#pragma comment(lib, "wsock32.lib")

#define SleepMiliSec(x)			Sleep(x)

#else //WIN32

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>


typedef int SOCKET;
#define INVALID_SOCKET -1
typedef REGISTER_SIZE REGSIZE;

#define SleepMiliSec(x)			usleep((x)<<10)
#endif// WIN32

#define ceil_divide(x, y) ((x) > 0? ( ((x) - 1) / (y) )+1 : 0)
#define pad_to_multiple(x, y) (ceil_divide(x, y) * (y))

typedef struct securitylevel
{
	uint32_t statbits;
	uint32_t symbits;
	uint32_t ifcbits;
	uint32_t eccpfbits;
	uint32_t ecckcbits;
} seclvl;


static const seclvl ST = {40, 80, 1024, 160, 163};
static const seclvl MT = {40, 112, 2048, 192, 233};
static const seclvl LT = {40, 128, 3072, 256, 283};
static const seclvl XLT = {40, 192, 7680, 384, 409};
static const seclvl XXLT = {40, 256, 15360, 512, 571};

enum psi_prot {NAIVE=0, TTP=1, DH_ECC=2, OT_PSI=3, PROT_LAST=4};


static int ceil_log2(int bits) {
	if(bits == 1) return 1;
	int targetlevel = 0, bitstemp = bits;
	while (bitstemp >>= 1) ++targetlevel;
	return targetlevel + ((1<<targetlevel) < bits);
}

static int floor_log2(int bits) {
	if(bits == 1) return 1;
	int targetlevel = 0;
	while (bits >>= 1) ++targetlevel;
	return targetlevel;
}


// Timing routines
static double getMillies(timeval timestart, timeval timeend)
{
	long time1 = (timestart.tv_sec * 1000000) + (timestart.tv_usec );
	long time2 = (timeend.tv_sec * 1000000) + (timeend.tv_usec );

	return (double)(time2-time1)/1000;
}

#endif /* TYPEDEFS_H_ */
