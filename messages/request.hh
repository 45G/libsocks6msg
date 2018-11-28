#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "../util/bytebuffer.hh"
#include "../fields/address.hh"
#include "../options/optionset.hh"

namespace S6M
{

class Request
{
	SOCKS6RequestCode commandCode;
	
	Address address;
	uint16_t port;
	
	OptionSet optionSet;
	
public:
	Request(SOCKS6RequestCode commandCode, Address address, uint16_t port);
	
	Request(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize();
	
	SOCKS6RequestCode getCommandCode() const
	{
		return commandCode;
	}
	
	const Address *getAddress() const
	{
		return &address;
	}
	
	uint16_t getPort() const
	{
		return port;
	}
	
	OptionSet *getOptionSet()
	{
		return &optionSet;
	}
};

}

#endif // SOCKS6MSG_REQUEST_HH
