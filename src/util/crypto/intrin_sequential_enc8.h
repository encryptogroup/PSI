/*
 * intrin_sequential_enc8.h
 * Copied and modified from Shay Gueron's code from intrinsic.h
/********************************************************************/
/* Copyright(c) 2014, Intel Corp.                                   */
/* Developers and authors: Shay Gueron (1) (2)                      */
/* (1) University of Haifa, Israel                                  */
/* (2) Intel, Israel                                                */
/* IPG, Architecture, Israel Development Center, Haifa, Israel      */
/********************************************************************/

#include "../typedefs.h"

#ifndef INTRIN_SEQUENTIAL_ENC8_H_
#define INTRIN_SEQUENTIAL_ENC8_H_

#ifdef AES256_HASH

#ifdef __cplusplus
extern "C" {
#endif

	void intrin_sequential_gen_rnd8(unsigned char* ctr_buf, const unsigned long long ctr, unsigned char* CT,
		int n_aesiters, int nkeys, unsigned char* ks, unsigned char* TEMP_BUF);
	void intrin_sequential_ksn(unsigned char* ks, unsigned char* key_bytes, int nkeys);
	void intrin_sequential_enc8(const unsigned char* PT, unsigned char* CT, int aes_niters, int nkeys, unsigned char* ks, unsigned char* TEMP_BUF);

#ifdef __cplusplus
};
#endif
#endif

#endif /* INTRIN_SEQUENTIAL_ENC8_H_ */
