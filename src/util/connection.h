/*
 * connection.h
 *
 *  Created on: Jul 1, 2014
 *      Author: mzohner
 */

#ifndef CONNECTION_H__
#define CONNECTION_H__

#include "typedefs.h"
#include "socket.h"
#include <sstream>

bool connect(const char* address, uint16_t port, CSocket& sockfd);
bool listen(const char* address, uint16_t port, CSocket* sockfd, uint32_t nconnections);

#define RETRY_CONNECT			1000
#define CONNECT_TIMEO_MILISEC	10000


#endif
