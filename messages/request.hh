#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "bytebuffer.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

class Request
{
	SOCKS6RequestCode commandCode;
	
	Address address;
	uint16_t port;
	
	OptionSet optionSet;
	
public:
	Request(SOCKS6RequestCode commandCode, Address address, uint16_t port)
		: commandCode(commandCode), address(address), port(port), optionSet(OptionSet::M_REQ) {}
	
	Request(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;
	
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

	const OptionSet *getOptionSet() const
	{
		return &optionSet;
	}
};

}

#endif // SOCKS6MSG_REQUEST_HH
