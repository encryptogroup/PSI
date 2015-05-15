/*
 * connection.cpp
 *
 *  Created on: Mar 7, 2013
 *      Author: mzohner
 */

#include "connection.h"

bool connect(const char* address, uint16_t port, CSocket& sockfd) {
        uint64_t lTO = CONNECT_TIMEO_MILISEC;
#ifdef DEBUG
        cout << "Connecting to " << address << ": " << port << endl;
#endif
		for( uint32_t i=0; i<RETRY_CONNECT; i++ ) {
			if( !sockfd.Socket() )
				goto connect_failure;
			if( sockfd.Connect( address, port, lTO)) {
#ifdef DEBUG
				cout << "Connection established" << endl;
#endif
				SleepMiliSec(10);
				return true;
			}
			SleepMiliSec(10);
			sockfd.Close();
        }

connect_failure:
        cout << " connection failed due to timeout!" << endl;
        return false;
}



bool listen(const char* address, uint16_t port, CSocket* sockfds, uint32_t nconnections) {
#ifdef DEBUG
        cout << "Listening: " << address << ":" << port << endl;
#endif
        uint32_t lid = nconnections-1;
        if( !sockfds[lid].Socket() ) {
		cerr << "Error: a socket could not be created " << endl;
                goto listen_failure;
        }
        if( !sockfds[lid].Bind(port,address) ) {
		cerr << "Error: a socket could not be bound" << endl;
                goto listen_failure;
        }
        if( !sockfds[lid].Listen() ) {
		cerr << "Error: could not listen on the socket " << endl;
                goto listen_failure;
        }

		for( uint32_t i = 0; i < nconnections; i++ )
		{
				CSocket sock;
				if( !sockfds[lid].Accept(sock) ) {
						cerr << "Error: could not accept connection" << endl;
		                goto listen_failure;
		        }

#ifdef DEBUG
				cout <<  "Connection with " << i << "-th client established" << endl;
#endif
				// locate the socket appropriately
				sockfds[i].AttachFrom(sock);
				sock.Detach();
		}

#ifdef DEBUG
        cout << "Listening finished"  << endl;
#endif
        return true;

listen_failure:
        cout << "Listen failed" << endl;
        return false;
}
