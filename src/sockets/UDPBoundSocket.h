//
// Created by Aleksey Timin on 11/21/19.
//

#ifndef EIPSCANNER_SOCKETS_UDPSBOUNDOCKET_H
#define EIPSCANNER_SOCKETS_UDPSBOUNDOCKET_H

#include <vector>
#include <chrono>
#include <memory>
//#include <netinet/in.h>
#include "UDPSocket.h"

namespace eipScanner {
namespace sockets {

	class UDPBoundSocket : public UDPSocket {
	public:
		using WPtr = std::weak_ptr<UDPBoundSocket>;
		using SPtr = std::shared_ptr<UDPBoundSocket>;

		explicit UDPBoundSocket(EndPoint endPoint);
		UDPBoundSocket(std::string host, int port);
		virtual ~UDPBoundSocket();

		// Join an IPv4 multicast group on this bound socket so a target's
		// T2O multicast producer is received. Dropped on destruction.
		void joinMulticastGroup(const struct in_addr& group);

	private:
		struct in_addr _multicastGroup{};
		bool _joinedMulticast = false;
	};
}
}

#endif  // EIPSCANNER_SOCKETS_UDPSOCKET_H
