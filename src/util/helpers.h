/*
 * helpers.h
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#include "socket.h"
#include "typedefs.h"

uint32_t exchange_information(uint32_t myneles, uint32_t mybytelen, uint32_t mysecparam, uint32_t mynthreads,
		uint32_t myprotocol, CSocket& sock) {

	uint32_t pneles, pbytelen, psecparam, pnthreads, pprotocol;
	//Send own values
	sock.Send(&myneles, sizeof(uint32_t));
	sock.Send(&mybytelen, sizeof(uint32_t));
	sock.Send(&mysecparam, sizeof(uint32_t));
	sock.Send(&mynthreads, sizeof(uint32_t));
	sock.Send(&myprotocol, sizeof(uint32_t));

	//Receive partner values
	sock.Receive(&pneles, sizeof(uint32_t));
	sock.Receive(&pbytelen, sizeof(uint32_t));
	sock.Receive(&psecparam, sizeof(uint32_t));
	sock.Receive(&pnthreads, sizeof(uint32_t));
	sock.Receive(&pprotocol, sizeof(uint32_t));

	//Assert
	assert(mybytelen == pbytelen);
	assert(mysecparam == psecparam);
	assert(mynthreads == pnthreads);
	assert(myprotocol == pprotocol);

	return pneles;
}

#endif /* HELPERS_H_ */
