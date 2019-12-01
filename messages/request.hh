#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "bytebuffer.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

struct Request
{
	SOCKS6RequestCode code;
	
	Address address;
	uint16_t port;
	
	OptionSet options { OptionSet::M_REQ };
	
	Request(SOCKS6RequestCode commandCode, Address address = Address(), uint16_t port = 0)
		: code(commandCode), address(address), port(port) {}
	
	Request(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
	
	size_t packedSize() const
	{
		return sizeof(SOCKS6Request) + address.packedSize() + options.packedSize();
	}
};

}

#endif // SOCKS6MSG_REQUEST_HH
