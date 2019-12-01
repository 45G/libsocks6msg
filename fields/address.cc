#include "sanity.hh"
#include "address.hh"

using namespace std;

namespace S6M
{

void Address::pack(ByteBuffer *bb)  const
{
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
	{
		in_addr *rawIPv4 = bb->get<in_addr>();
		*rawIPv4 = get<in_addr>(u);
		break;
	}
		
	case SOCKS6_ADDR_IPV6:
	{
		in6_addr *rawIPv6 = bb->get<in6_addr>();
		*rawIPv6 = get<in6_addr>(u);
		break;
	}
		
	case SOCKS6_ADDR_DOMAIN:
		get<Padded<String>>(u).pack(bb);
		break;
	}
}

Address::Address(SOCKS6AddressType type, ByteBuffer *bb)
	: type(type)
{
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
	{
		u = *bb->get<in_addr>();
		break;
	}
		
	case SOCKS6_ADDR_IPV6:
	{
		u = *bb->get<in6_addr>();
		break;
	}
		
	case SOCKS6_ADDR_DOMAIN:
		u = Padded<String>(bb);
		break;

	default:
		throw BadAddressTypeException();
	}
}

}
