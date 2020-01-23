#ifndef SOCKS6MSG_OPREPLY_HH
#define SOCKS6MSG_OPREPLY_HH

#include "socksmessagebase.hh"
#include "address.hh"
#include "optionset.hh"

namespace S6M
{

struct OperationReply: public SOCKSMessageBase<SOCKS6OperationReply>
{
	SOCKS6OperationReplyCode code;
	
	Address  address;
	uint16_t port;
	
	OptionSet options { OptionSet::M_OP_REP };
	
	OperationReply(SOCKS6OperationReplyCode code, Address address = Address(), uint16_t port = 0)
		: code(code), address(address), port(port) {}
	
	OperationReply(ByteBuffer *bb)
		: SOCKSMessageBase(bb),
		  code((SOCKS6OperationReplyCode)rawMessage->code),
		  address((SOCKS6AddressType)rawMessage->addressType, bb),
		  port(ntohs(rawMessage->bindPort)),
		  options(bb, OptionSet::M_OP_REP, ntohs(rawMessage->optionsLength)) {}
	
	void pack(ByteBuffer *bb) const
	{
		SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
		
		rawOpReply->version       = SOCKS6_VERSION;
		rawOpReply->code          = code;
		rawOpReply->optionsLength = htons(options.packedSize());
		rawOpReply->bindPort      = htons(port);
		rawOpReply->padding       = 0;
		rawOpReply->addressType   = address.getType();
		
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
		return sizeof(SOCKS6OperationReply) + address.packedSize() + options.packedSize();
	}
};

}

#endif // SOCKS6MSG_OPREPLY_HH
