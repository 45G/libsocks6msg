#ifndef SOCKS6MSG_ADDRESS_HH
#define SOCKS6MSG_ADDRESS_HH

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string>
#include <vector>
#include "socks6msg_bytebuffer.hh"
#include "socks6msg_string.hh"

namespace S6M
{

class Address
{
	SOCKS6AddressType type;
	
	in_addr ipv4;
	in6_addr ipv6;
	String domain;
	
public:
	size_t packedSize();
	
	void pack(ByteBuffer *bb);
	
	Address()
		: type((SOCKS6AddressType)0) {}
	
	Address(in_addr ipv4)
		: type(SOCKS6_ADDR_IPV4), ipv4(ipv4) {}
	
	Address(in6_addr ipv6)
		: type(SOCKS6_ADDR_IPV6), ipv6(ipv6) {}
	
	Address(std::string domain)
		: domain(domain) {}
	
	Address(ByteBuffer *bb);
	
	SOCKS6AddressType getType() const
	{
		return type;
	}
	
	in_addr getIPv4() const;
	in6_addr getIPv6() const;
	std::string getDomain() const;
};

}

#endif // SOCKS6MSG_ADDRESS_HH