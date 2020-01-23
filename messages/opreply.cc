#include "opreply.hh"
#include "sanity.hh"
#include "version.hh"
#include "restrictedint.hh"

namespace S6M
{

OperationReply::OperationReply(ByteBuffer *bb)
{
	SOCKSVersion::check(bb);
	
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code    = (SOCKS6OperationReplyCode)rawOpReply->code;
	port    = ntohs(rawOpReply->bindPort);
	address = Address((SOCKS6AddressType)rawOpReply->addressType, bb);
	options = OptionSet(bb, OptionSet::M_OP_REP, ntohs(rawOpReply->optionsLength));
}

void OperationReply::pack(ByteBuffer *bb) const
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

}
