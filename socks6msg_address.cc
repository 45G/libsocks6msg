#include "socks6msg_address.hh"

using namespace std;

namespace S6M
{

Address *Address::parse(ByteBuffer *bb)
{
	//TODO
}

size_t Address::packedSize()
{
	//TODO
}

void Address::pack(ByteBuffer *bb)
{
	//TODO
}

Address::Address(string domain)
	: domain(domain)
{
	if (domain.length() == 0 || domain.length() > 255 | domain.find_first_of('\0') != string::npos)
		throw Exception(S6M_ERR_INVALID);
}

Address::Address(SOCKS6AddressType type, vector<uint8_t> data)
	: type(type)
{
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
		if (data.size() != sizeof(in_addr))
			throw Exception(S6M_ERR_INVALID);
		memcpy(&ipv4, data.data(), data.size());
		break;
		
	case SOCKS6_ADDR_IPV6:
		if (data.size() != sizeof(in6_addr))
			throw Exception(S6M_ERR_INVALID);
		memcpy(&ipv6, data.data(), data.size());
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		if (data.size() < 1 || data.size() > 255 || data.contains(0))
			throw Exception(S6M_ERR_INVALID);
		domain = string(data.data());
		break;
		
	default:
		this->data = data;
	}
}

in_addr Address::getIPv4() const
{
	if (type != SOCKS6_ADDR_IPV4)
		throw Exception(S6M_ERR_INVALID);
	
	return ipv4;
}

in6_addr Address::getIPv6() const
{
	if (type != SOCKS6_ADDR_IPV6)
		throw Exception(S6M_ERR_INVALID);
	
	return ipv6;
}

string Address::getDomain() const
{
	if (type != SOCKS6_ADDR_DOMAIN)
		throw Exception(S6M_ERR_INVALID);
	
	return domain;
}

vector Address::getData() const
{
	if (type == SOCKS6_ADDR_IPV4 || type == SOCKS6_ADDR_IPV6 || type == SOCKS6_ADDR_DOMAIN)
		throw Exception(S6M_ERR_INVALID);
	
	return data;
}

}
