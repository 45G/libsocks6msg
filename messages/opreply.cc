#include "opreply.hh"
#include "sanity.hh"
#include "version.hh"
#include "restrictedint.hh"

namespace S6M
{

OperationReply::OperationReply(ByteBuffer *bb)
{
	Version::check(bb);
	
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code = enumCast<SOCKS6OperationReplyCode>(rawOpReply->code);
	port = ntohs(rawOpReply->bindPort);
	SOCKS6AddressType addrType = enumCast<SOCKS6AddressType>(rawOpReply->addressType);
	
	address = Address(addrType, bb);
	
	OptionsLength optionsLength(ntohs(rawOpReply->optionsLength));
	
	options = OptionSet(bb, OptionSet::M_OP_REP, optionsLength);
}

void OperationReply::pack(ByteBuffer *bb) const
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	rawOpReply->version = SOCKS6_VERSION;
	rawOpReply->code = code;
	rawOpReply->optionsLength = htons(options.packedSize());
	rawOpReply->bindPort = htons(port);
	rawOpReply->padding = 0;
	rawOpReply->addressType = address.getType();
	
	address.pack(bb);
	
	options.pack(bb);
}

}
