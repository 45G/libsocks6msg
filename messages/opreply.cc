#include "opreply.hh"
#include "../util/sanity.hh"

namespace S6M
{

OperationReply::OperationReply(ByteBuffer *bb)
	: optionSet(OptionSet::M_OP_REP)
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code = enumCast<SOCKS6OperationReplyCode>(rawOpReply->code);
	port = ntohs(rawOpReply->bindPort);
	
	address = Address(bb);
	
	optionSet = OptionSet(bb, OptionSet::M_OP_REP);
}

void OperationReply::pack(ByteBuffer *bb) const
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	rawOpReply->code = code;
	rawOpReply->bindPort = htons(port);
	
	address.pack(bb);
	
	optionSet.pack(bb);
}

size_t OperationReply::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t OperationReply::packedSize()
{
	return sizeof(SOCKS6OperationReply) + address.packedSize() + optionSet.packedSize();
}

}
