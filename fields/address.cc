#include "address.hh"

using namespace std;

namespace S6M
{

size_t Address::packedSize()
{
	size_t size = 1;
	
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
		size += sizeof(in_addr);
		break;
		
	case SOCKS6_ADDR_IPV6:
		size += sizeof(in6_addr);
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		size += domain.packedSize();
		break;
	}
	
	return size;
}

void Address::pack(ByteBuffer *bb)  const
{
	uint8_t *rawType = bb->get<uint8_t>();
	*rawType = type;
	
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
	{
		in_addr *rawIPv4 = bb->get<in_addr>();
		*rawIPv4 = ipv4;
		break;
	}
		
	case SOCKS6_ADDR_IPV6:
	{
		in6_addr *rawIPv6 = bb->get<in6_addr>();
		*rawIPv6 = ipv6;
		break;
	}
		
	case SOCKS6_ADDR_DOMAIN:
		domain.pack(bb);
		break;
	}
}

in_addr Address::getIPv4() const
{
	if (type != SOCKS6_ADDR_IPV4)
		throw InvalidFieldException();
	
	return ipv4;
}

in6_addr Address::getIPv6() const
{
	if (type != SOCKS6_ADDR_IPV6)
		throw InvalidFieldException();
	
	return ipv6;
}

const std::shared_ptr<string> Address::getDomain() const
{
	if (type != SOCKS6_ADDR_DOMAIN)
		throw InvalidFieldException();
	
	return domain.getStr();
}

Address::Address(ByteBuffer *bb)
{
	uint8_t *rawType = bb->get<uint8_t>();
	type = (SOCKS6AddressType)(*rawType);
	
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
	{
		in_addr *rawIPv4 = bb->get<in_addr>();
		ipv4 = *rawIPv4;
		break;
	}
		
	case SOCKS6_ADDR_IPV6:
	{
		in6_addr *rawIPv6 = bb->get<in6_addr>();
		ipv6 = *rawIPv6;
		break;
	}
		
	case SOCKS6_ADDR_DOMAIN:
		domain = String(bb);
		break;
		
	default:
		throw InvalidFieldException();
	}
}

}
