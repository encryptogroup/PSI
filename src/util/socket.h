//socket.h

#ifndef __SOCKET_H__BY_SGCHOI
#define __SOCKET_H__BY_SGCHOI 

#include "typedefs.h"

#define TRACK_COMMUNICATION

class CSocket 
{
public:
	CSocket(){
		m_hSock = INVALID_SOCKET;
#ifdef TRACK_COMMUNICATION
		bytes_sent = 0;
		bytes_received = 0;
#endif
	}
	~CSocket(){ }
	//~CSocket(){ cout << "Closing Socket!" << endl; Close(); }
	
#ifdef TRACK_COMMUNICATION
	uint64_t get_bytes_sent() { return bytes_sent; };
	uint64_t get_bytes_received() { return bytes_received; };
#endif

public:
	bool Socket()
	{
		bool success = false;

		#ifdef WIN32
		static bool s_bInit = FALSE;

		if (!s_bInit) {
		  WORD wVersionRequested;
		  WSADATA wsaData;

		  wVersionRequested = MAKEWORD(2, 0);     
		  WSAStartup(wVersionRequested, &wsaData);
		  s_bInit = TRUE; 
		}
		#endif
		
		Close();

		success =  (m_hSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET; 

		return success;
	
	}

	void Close()
	{
		if( m_hSock == INVALID_SOCKET ) return;
		
		#ifdef WIN32
		shutdown(m_hSock, SD_SEND);
		closesocket(m_hSock);
		#else
		shutdown(m_hSock, SHUT_WR);
		close(m_hSock);
		#endif
  
		m_hSock = INVALID_SOCKET; 
	} 

	void AttachFrom(CSocket& s)
	{
		m_hSock = s.m_hSock;
	}

	void Detach()
	{
		m_hSock = INVALID_SOCKET;
	}

public:
	string GetIP()
	{
		sockaddr_in addr;
		uint32_t addr_len = sizeof(addr);

		if (getsockname(m_hSock, (sockaddr *) &addr, (socklen_t *) &addr_len) < 0) return "";
		return inet_ntoa(addr.sin_addr);
	}


	uint16_t GetPort()
	{
		sockaddr_in addr;
		uint32_t addr_len = sizeof(addr);

		if (getsockname(m_hSock, (sockaddr *) &addr, (socklen_t *) &addr_len) < 0) return 0;
		return ntohs(addr.sin_port);
	}
	
	bool Bind(uint16_t nPort=0, const char* ip = "")
	{
		// Bind the socket to its port
		sockaddr_in sockAddr;
		memset(&sockAddr,0,sizeof(sockAddr));
		sockAddr.sin_family = AF_INET;

		if( strcmp(ip, "") )
		{
			int on = 1;
			setsockopt(m_hSock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof(on));

			sockAddr.sin_addr.s_addr = inet_addr(ip);

			if (sockAddr.sin_addr.s_addr == INADDR_NONE)
			{
				hostent* phost;
				phost = gethostbyname(ip);
				if (phost != NULL)
					sockAddr.sin_addr.s_addr = ((in_addr*)phost->h_addr)->s_addr;
				else
					return false;
			}
		}
		else
		{
			sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		}
		
		sockAddr.sin_port = htons(nPort);

		return bind(m_hSock, (sockaddr *) &sockAddr, sizeof(sockaddr_in)) >= 0; 
	}

	bool Listen(int nQLen = 5)
	{
		return listen(m_hSock, nQLen) >= 0;
	} 

	bool Accept(CSocket& sock)
	{
		sock.m_hSock = accept(m_hSock, NULL, 0);
		if( sock.m_hSock == INVALID_SOCKET ) return false;
 
		return true;
	}
	 
	bool Connect(const char* ip, uint16_t port, int64_t lTOSMilisec = -1)
	{
		//cout << "Socket " << m_hSock << " connected" << endl;
		sockaddr_in sockAddr;
		memset(&sockAddr,0,sizeof(sockAddr));
		sockAddr.sin_family = AF_INET;
		sockAddr.sin_addr.s_addr = inet_addr(ip);

		if (sockAddr.sin_addr.s_addr == INADDR_NONE)
		{
			hostent* lphost;
			lphost = gethostbyname(ip);
			if (lphost != NULL)
				sockAddr.sin_addr.s_addr = ((in_addr*)lphost->h_addr)->s_addr;
			else
				return false;
		}

		sockAddr.sin_port = htons(port);

#ifdef WIN32

		DWORD dw = 100000;

		if( lTOSMilisec > 0 )
		{
			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, (char*) &lTOSMilisec, sizeof(lTOSMilisec));
		}

		int ret = connect(m_hSock, (sockaddr*)&sockAddr, sizeof(sockAddr));
		
		if( ret >= 0 && lTOSMilisec > 0 )
			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, (char*) &dw, sizeof(dw));
	
#else
	
		timeval	tv;
		
		if( lTOSMilisec > 0 )
		{
			tv.tv_sec = lTOSMilisec/1000;
			tv.tv_usec = (lTOSMilisec%1000)*1000;
	
			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}

		int ret = connect(m_hSock, (sockaddr*)&sockAddr, sizeof(sockAddr));
		
		if( ret >= 0 && lTOSMilisec > 0 )
		{
			tv.tv_sec = 100000; 
			tv.tv_usec = 0;

			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}

#endif
		return ret >= 0;
	}

	int Receive(void* pBuf, int nLen, int nFlags = 0)
	{
		//cout << "Socket " << m_hSock << " (" << (unsigned long long) this << ") receiving " << nLen << " bytes" << endl;
		char* p = (char*) pBuf;
		int n = nLen;
		int ret = 0;
		while( n > 0 )
        {
			ret = recv(m_hSock, p, n, 0);
#ifdef WIN32
			if( ret <= 0 )
			{
				return ret;
			}
#else
            if( ret < 0 )
            {
				if( errno == EAGAIN )
				{
					cerr << "socket recv eror: EAGAIN" << endl;
					SleepMiliSec(200);
					continue;
				} 
				else
				{
					cerr << "socket recv error: " << errno << endl;
					perror("Socket error ");
					return ret;
				}
            }
			else if (ret == 0)
			{
				return ret;
			} 
#endif
      
            p += ret;
            n -= ret;
        }

#ifdef TRACK_COMMUNICATION
		bytes_received += ((uint64_t) nLen);
		//cout << "bytes_received = " << bytes_received << endl;
#endif
		return nLen;
 	}
 
	int Send(const void* pBuf, int nLen, int nFlags = 0)
	{
		//cout << "Socket " << m_hSock << " (" << (unsigned long long) this << ") sending " << nLen << " bytes" << endl;
#ifdef TRACK_COMMUNICATION
		bytes_sent+= ((uint64_t) nLen);
		//cout << "bytes_sent = " << bytes_sent << endl;
#endif
		return send(m_hSock, (char*)pBuf, nLen, nFlags);
	}	
	  
private:
	SOCKET	m_hSock;
#ifdef TRACK_COMMUNICATION
	uint64_t bytes_sent;
	uint64_t bytes_received;
#endif

};


#endif //SOCKET_H__BY_SGCHOI

