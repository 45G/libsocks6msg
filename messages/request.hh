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
	
public:
	OptionSet options;
	
	Request(SOCKS6RequestCode commandCode, Address address = Address(), uint16_t port = 0)
		: commandCode(commandCode), address(address), port(port), options(OptionSet::M_REQ) {}
	
	Request(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;

	void setCommandCode(SOCKS6RequestCode commandCode)
	{
		this->commandCode = commandCode;
	}
	
	SOCKS6RequestCode getCommandCode() const
	{
		return commandCode;
	}
	
	void setAddress(const Address &address)
	{
		this->address = address;
	}

	const Address *getAddress() const
	{
		return &address;
	}

	void setPort(uint16_t port)
	{
		this->port = port;
	}
	
	uint16_t getPort() const
	{
		return port;
	}
};

}

#endif // SOCKS6MSG_REQUEST_HH
