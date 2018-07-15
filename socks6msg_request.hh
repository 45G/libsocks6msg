#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "socks6msg_bytebuffer.hh"
#include "socks6msg_address.hh"
#include "socks6msg_optionset.hh"

namespace S6M
{

class Request
{
	SOCKS6RequestCode commandCode;
	
	Address address;
	uint16_t port;
	
	uint16_t initialDataLen;
	
	OptionSet optionSet;
	
public:
	Request(SOCKS6RequestCode commandCode, Address address, uint16_t port, uint16_t initialDataLen, const OptionSet &optionSet = OptionSet(OptionSet::M_REQ));
	
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
	
	const OptionSet *getOptionSet() const
	{
		return &optionSet;
	}
	
	uint16_t getInitialDataLen() const
	{
		return initialDataLen;
	}
};

}

#endif // SOCKS6MSG_REQUEST_HH
