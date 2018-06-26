#ifndef SOCKS6MSG_OPREPLY_HH
#define SOCKS6MSG_OPREPLY_HH

#include "socks6msg_bytebuffer.hh"
#include "socks6msg_address.hh"
#include "socks6msg_optionset.hh"

namespace S6M
{

class OperationReply
{
	SOCKS6OperationReplyCode code;
	
	Address address;
	uint16_t port;
	
	uint16_t initDataOff;
	
	OptionSet optionSet;
	
public:
	OperationReply(SOCKS6OperationReplyCode code, Address address, uint16_t port, uint16_t initDataOff, OptionSet optionSet);
	
	OperationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize();
	
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
	
	uint16_t getInitDataOff() const
	{
		return initDataOff;
	}
	
	const OptionSet *getOptionSet() const
	{
		return &optionSet;
	}
};

}

#endif // SOCKS6MSG_OPREPLY_HH
