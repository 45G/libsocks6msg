#include "opreply.hh"
#include "sanity.hh"
#include "version.hh"

namespace S6M
{

OperationReply::OperationReply(ByteBuffer *bb)
	: optionSet(OptionSet::M_OP_REP)
{
	Version::check(bb);
	
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code = enumCast<SOCKS6OperationReplyCode>(rawOpReply->code);
	port = ntohs(rawOpReply->bindPort);
	
	address = Address(bb);
	
	optionSet = OptionSet(bb, OptionSet::M_OP_REP, ntohs(rawOpReply->optionsLength));
}

void OperationReply::pack(ByteBuffer *bb) const
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	rawOpReply->version = SOCKS6_VERSION;
	rawOpReply->code = code;
	rawOpReply->optionsLength = htons(optionSet.packedSize());
	rawOpReply->bindPort = htons(port);
	rawOpReply->padding = 0;
	
	address.pack(bb);
	
	optionSet.pack(bb);
}

size_t OperationReply::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t OperationReply::packedSize() const
{
	return sizeof(SOCKS6OperationReply) + address.packedSize() + optionSet.packedSize();
}

}
