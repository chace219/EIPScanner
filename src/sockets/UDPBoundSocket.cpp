//
// Created by Aleksey Timin on 11/21/19.
//
#include <system_error>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__)
#include <netinet/in.h>
#include <arpa/inet.h>
#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <ws2tcpip.h>
#endif

#include "UDPBoundSocket.h"
#include "Platform.h"

namespace eipScanner {
namespace sockets {


	UDPBoundSocket::UDPBoundSocket(std::string host, int port)
		: UDPBoundSocket(EndPoint(host, port)) {

	}
	UDPBoundSocket::UDPBoundSocket(EndPoint endPoint)
		: UDPSocket(std::move(endPoint)) {
		int on = 1;
		if (setsockopt(_sockedFd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
			throw std::system_error(BaseSocket::getLastError(), BaseSocket::getErrorCategory());
		}

		auto addr = _remoteEndPoint.getAddr();
		addr.sin_addr.s_addr = INADDR_ANY;
		if (bind(_sockedFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			throw std::system_error(BaseSocket::getLastError(), BaseSocket::getErrorCategory());
		}
	}

	void UDPBoundSocket::joinMulticastGroup(const struct in_addr& group) {
		struct ip_mreq mreq;
		std::memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr = group;
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(_sockedFd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				(char *) &mreq, sizeof(mreq)) < 0) {
			throw std::system_error(BaseSocket::getLastError(), BaseSocket::getErrorCategory());
		}
		_multicastGroup = group;
		_joinedMulticast = true;
	}

	sockets::UDPBoundSocket::~UDPBoundSocket() {
		if (_joinedMulticast) {
			struct ip_mreq mreq;
			std::memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr = _multicastGroup;
			mreq.imr_interface.s_addr = htonl(INADDR_ANY);
			setsockopt(_sockedFd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
				(char *) &mreq, sizeof(mreq));
		}
	}
}
}
