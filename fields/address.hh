#ifndef SOCKS6MSG_ADDRESS_HH
#define SOCKS6MSG_ADDRESS_HH

#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <vector>
#include <optional>
#include <variant>
#include "socks6.h"
#include "bytebuffer.hh"
#include "string.hh"
#include "padded.hh"
#include "exceptions.hh"

namespace S6M
{

class Address
{
	SOCKS6AddressType type = SOCKS6_ADDR_IPV4;
	
	std::variant<in_addr, in6_addr, Padded<String>> u = in_addr({ 0 });
	
public:
	size_t packedSize() const
	{
		switch (type)
		{
		case SOCKS6_ADDR_IPV4:
			return sizeof(in_addr);
			
		case SOCKS6_ADDR_IPV6:
			return sizeof(in6_addr);
			
		case SOCKS6_ADDR_DOMAIN:
			return std::get<Padded<String>>(u).packedSize();
		}
		
		/* never happens */
		assert(false);
		return 0;
	}
	
	void pack(ByteBuffer *bb) const;
	
	Address() = default;
	
	Address(in_addr ipv4)
		: type(SOCKS6_ADDR_IPV4), u(ipv4) {}
	
	Address(in6_addr ipv6)
		: type(SOCKS6_ADDR_IPV6), u(ipv6) {}
	
	Address(const std::string_view &domain)
		: type(SOCKS6_ADDR_DOMAIN), u(domain) {}
	
	Address(SOCKS6AddressType type, ByteBuffer *bb);
	
	SOCKS6AddressType getType() const
	{
		return type;
	}
	
	in_addr getIPv4() const
	{
		return std::get<in_addr>(u);
	}
	
	in6_addr getIPv6() const
	{
		return std::get<in6_addr>(u);
	}
	
	const std::string *getDomain() const
	{
		return std::get<Padded<String>>(u).getStr();
	}
	
	bool isZero() const
	{
		return ( type == SOCKS6_ADDR_IPV4 && std::get<in_addr>(u).s_addr   == INADDR_ANY) ||
			(type == SOCKS6_ADDR_IPV6 && std::get<in6_addr>(u).s6_addr == in6addr_any.s6_addr);
	}
};

}

#endif // SOCKS6MSG_ADDRESS_HH
