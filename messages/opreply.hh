#ifndef SOCKS6MSG_OPREPLY_HH
#define SOCKS6MSG_OPREPLY_HH

#include "bytebuffer.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

struct OperationReply
{
	SOCKS6OperationReplyCode code;
	
	Address  address;
	uint16_t port;
	
	OptionSet options { OptionSet::M_OP_REP };
	
	OperationReply(SOCKS6OperationReplyCode code, Address address = Address(), uint16_t port = 0)
		: code(code), address(address), port(port) {}
	
	OperationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
	
	size_t packedSize() const
	{
		return sizeof(SOCKS6OperationReply) + address.packedSize() + options.packedSize();
	}
};

}

#endif // SOCKS6MSG_OPREPLY_HH
