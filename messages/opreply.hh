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
	
public:
	OptionSet options;
	
	OperationReply(SOCKS6OperationReplyCode code, Address address = Address(), uint16_t port = 0)
		: code(code), address(address), port(port), options(OptionSet::M_OP_REP) {}

	OperationReply()
		: OperationReply(SOCKS6_OPERATION_REPLY_FAILURE) {}
	
	OperationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;
	
	void setCode(SOCKS6OperationReplyCode code)
	{
		this->code = code;
	}

	SOCKS6OperationReplyCode getCode() const
	{
		return code;
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

#endif // SOCKS6MSG_OPREPLY_HH
