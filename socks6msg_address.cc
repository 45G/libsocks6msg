#include "socks6msg_address.hh"

using namespace std;

namespace S6M
{

Address *Address::parse(ByteBuffer *bb)
{
	uint8_t *rawType = bb->get<uint8_t>();
	SOCKS6AddressType type = (SOCKS6AddressType)(*rawType);
	
	//TODO
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
		
	default:
		size += data.size();
		break;
	}
	
}

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
		
	default:
		size += data.size();
		break;
	}
	
	return size;
}

void Address::pack(ByteBuffer *bb)
{
	uint8_t *rawType = bb->get<uint8_t>();
	*rawType = type;
	
	uint8_t *rawData; 
	
	switch (type)
	{
	case SOCKS6_ADDR_IPV4:
		rawData = bb->get<uint8_t>(sizeof(in_addr));
		memcpy(rawData, &ipv4, sizeof(in_addr));
		break;
		
	case SOCKS6_ADDR_IPV6:
		rawData = bb->get<uint8_t>(sizeof(in6_addr));
		memcpy(rawData, &ipv4, sizeof(in6_addr));
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		domain.pack(bb);
		break;
		
	default:
		rawData = bb->get<uint8_t>(data.size());
		memcpy(rawData, data.data(), data.size());
		break;
	}
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
		domain = String(data);
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
