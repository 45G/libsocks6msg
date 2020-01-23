#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "socksmessagebase.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

struct Request: public MessageBase<SOCKS6Request>
{
	SOCKS6RequestCode code;
	
	Address  address;
	uint16_t port;
	
	OptionSet options { OptionSet::M_REQ };
	
	Request(SOCKS6RequestCode commandCode, Address address = Address(), uint16_t port = 0)
		: code(commandCode), address(address), port(port) {}
	
	Request(ByteBuffer *bb)
		: MessageBase(bb),
		  code((SOCKS6RequestCode)rawMessage->commandCode),
		  address((SOCKS6AddressType)rawMessage->addressType, bb),
		  port(ntohs(rawMessage->port)),
		  options(bb, OptionSet::M_REQ, ntohs(rawMessage->optionsLength)) {}
	
	void pack(ByteBuffer *bb) const
	{
		SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
		
		rawRequest->version       = SOCKS6_VERSION;
		rawRequest->commandCode   = code;
		rawRequest->optionsLength = htons(options.packedSize());
		rawRequest->port          = htons(port);
		rawRequest->padding       = 0;
		rawRequest->addressType   = address.getType();
		
		address.pack(bb);
		options.pack(bb);
	}
	
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
