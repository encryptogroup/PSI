/*
 * crypto.h
 *
 *  Created on: Jul 9, 2014
 *      Author: mzohner
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <sys/stat.h>
#include <fcntl.h>

#include "../typedefs.h"
#include "pk-crypto.h"
#include "gmp-pk-crypto.h"
#include "ecc-pk-crypto.h"
#include "../codewords.h"
#include "../socket.h"
#include "TedKrovetzAesNiWrapperC.h"
#include "intrin_sequential_enc8.h"


#define AES_BYTES 16
#define AES_BITS AES_BYTES*8

#define SHA1_OUT_BYTES 20
#define SHA256_OUT_BYTES 32
#define SHA512_OUT_BYTES 64

const uint8_t ZERO_IV[AES_BYTES]={0};

const uint8_t const_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};



enum bc_mode {ECB, CBC};

//Check for the OpenSSL version number, since the EVP_CIPHER_CTX has become opaque from >= 1.1.0
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	#define OPENSSL_OPAQUE_EVP_CIPHER_CTX
#endif


#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
typedef EVP_CIPHER_CTX* AES_KEY_CTX;
#else
typedef EVP_CIPHER_CTX AES_KEY_CTX;
#endif

struct prf_state_ctx {
	AES_KEY_CTX aes_key;
#ifdef AES256_HASH
	ROUND_KEYS aes_pipe_key;
#endif
	uint64_t* ctr;
};


//TODO: not thread-secure when multiple threads generate random data
class crypto {

public:

	crypto(uint32_t symsecbits, uint8_t* seed);
	crypto(uint32_t symsecbits);
	~crypto();

	//Randomness generation routines
	void gen_rnd(uint8_t* resbuf, uint32_t numbytes);
#ifdef AES256_HASH
	void gen_rnd_pipelined(uint8_t* resbuf, uint32_t numbytes);
#endif

	//void gen_rnd(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes);
	void gen_rnd_uniform(uint8_t* resbuf, uint64_t mod);
	void gen_rnd_perm(uint32_t* perm, uint32_t neles);

	//Encryption routines
	void encrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);
	void decrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);

	//Hash routines
	void hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes);
	void hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* tmpbuf);
	void hash_ctr(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint64_t ctr);
	void fixed_key_aes_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes);
	void fixed_key_aes_hash_ctr(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes);

	void aes_cbc_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);
	void aes_compression_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);


	//Key seed routines
	void seed_aes_hash(uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV);
	void seed_aes_enc(uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV);

	//External encryption routines
	void init_aes_key(AES_KEY_CTX* aes_key, uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV);
	void init_aes_key(AES_KEY_CTX* aes_key, uint32_t symbits, uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV);
	void clean_aes_key(AES_KEY_CTX* aeskey);
	uint32_t get_aes_key_bytes();
	void encrypt(AES_KEY_CTX* enc_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);
	void decrypt(AES_KEY_CTX* dec_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes);

	pk_crypto* gen_field(field_type ftype);

	seclvl get_seclvl() {return secparam;};
	uint32_t get_hash_bytes();

	void gen_common_seed(prf_state_ctx* aes_key, CSocket& sock);
	void init_prf_state(prf_state_ctx* prf_state, uint8_t* seed);

private:
	void seed_aes_key(AES_KEY_CTX* aeskey, uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV, bool encrypt=true);
	void seed_aes_key(AES_KEY_CTX* aeskey, uint32_t symseclvl, uint8_t* seed, bc_mode mode=ECB, const uint8_t* iv=ZERO_IV, bool encrypt=true);
	void init(uint32_t symsecbits, uint8_t* seed);
	void free_prf_state(prf_state_ctx* prf_state);

	AES_KEY_CTX aes_hash_key;
	AES_KEY_CTX aes_enc_key;
	AES_KEY_CTX aes_dec_key;
	prf_state_ctx global_prf_state;
	//AES_KEY_CTX aes_rnd_key;

	seclvl secparam;
	//uint64_t* rndctr;
	uint8_t* aes_hash_in_buf;
	uint8_t* aes_hash_out_buf;
	uint8_t* aes_hash_buf_y1;
	uint8_t* aes_hash_buf_y2;

	uint8_t* sha_hash_buf;

	void (*hash_routine)(uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*);
};


//Some functions that should be useable without the class
void sha1_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf);
void sha256_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf);
void sha512_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf);
void gen_secure_random(uint8_t* dest, uint32_t nbytes);
void gen_rnd_bytes(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes);
#ifdef AES256_HASH
void gen_rnd_bytes_pipelined(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes);
#endif

seclvl get_sec_lvl(uint32_t symsecbits);

static const uint32_t m_nCodeWordBits = 512;
static const uint32_t m_nCodeWordBytes = m_nCodeWordBits/8;

static void InitAndReadCodeWord(REGISTER_SIZE*** codewords) {
	uint32_t ncodewords = m_nCodeWordBits;
	uint32_t ncwintlen = 8;
	*codewords = (REGISTER_SIZE**) malloc(sizeof(REGISTER_SIZE*) * ncodewords);
	for(uint32_t i = 0; i < ncodewords; i++) {
		(*codewords)[i] = (REGISTER_SIZE*) malloc(sizeof(REGISTER_SIZE) * ((ncwintlen * sizeof(uint32_t)) / sizeof(REGISTER_SIZE)));
	}
	readCodeWords(*codewords);
}


#endif /* CRYPTO_H_ */
