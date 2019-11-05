#ifndef SOCKS6MSG_ADDRESS_HH
#define SOCKS6MSG_ADDRESS_HH

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <vector>
#include <optional>
#include "socks6.h"
#include "bytebuffer.hh"
#include "string.hh"
#include "padded.hh"
#include "exceptions.hh"

namespace S6M
{

class Address
{
	SOCKS6AddressType type;
	
	in_addr ipv4;
	in6_addr ipv6;
	std::optional<Padded<String>> domain;
	
public:
	size_t packedSize() const;
	
	void pack(ByteBuffer *bb) const;
	
	Address(SOCKS6AddressType type = SOCKS6_ADDR_IPV4)
		: type(type)
	{
		if (type == SOCKS6_ADDR_IPV4)
		{
			ipv4.s_addr = 0;
		}
		else if (type == SOCKS6_ADDR_IPV6)
		{
			for (int i = 0; i < 4; i++)
				ipv6.__in6_u.__u6_addr32[i] = 0;
		}
		else
		{
			throw BadAddressTypeException();
		}
	}
	
	Address(in_addr ipv4)
		: type(SOCKS6_ADDR_IPV4), ipv4(ipv4) {}
	
	Address(in6_addr ipv6)
		: type(SOCKS6_ADDR_IPV6), ipv6(ipv6) {}
	
	Address(const std::string &domain)
		: type(SOCKS6_ADDR_DOMAIN), domain(domain) {}
	
	Address(SOCKS6AddressType type, ByteBuffer *bb);
	
	SOCKS6AddressType getType() const
	{
		return type;
	}
	
	in_addr getIPv4() const
	{
		return ipv4;
	}
	
	in6_addr getIPv6() const
	{
		return ipv6;
	}
	
	const std::string *getDomain() const
	{
		return (*domain).getStr();
	}
};

}

#endif // SOCKS6MSG_ADDRESS_HH
