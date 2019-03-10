#ifndef SOCKS6MSG_OPREPLY_HH
#define SOCKS6MSG_OPREPLY_HH

#include "bytebuffer.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

class OperationReply
{
	SOCKS6OperationReplyCode code;
	
	Address address;
	uint16_t port;
	
	OptionSet optionSet;
	
public:
	OperationReply(SOCKS6OperationReplyCode code, Address address, uint16_t port)
		: code(code), address(address), port(port), optionSet(OptionSet::M_OP_REP) {}
	
	OperationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;
	
	SOCKS6OperationReplyCode getCode() const
	{
		return code;
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

#endif // SOCKS6MSG_OPREPLY_HH