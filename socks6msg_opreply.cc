#include "socks6msg_opreply.hh"
#include "socks6msg_sanity.hh"

namespace S6M
{

OperationReply::OperationReply(SOCKS6OperationReplyCode code, Address address, uint16_t port, uint16_t initDataOff, OptionSet optionSet)
	: code(code), address(address), port(port), initDataOff(initDataOff), optionSet(optionSet)
{
	if (address.getType() == Address::INVALID_TYPE)
		throw InvalidFieldException();
		
	if (optionSet.getMode() != OptionSet::M_OP_REP)
		throw InvalidFieldException();
}

OperationReply::OperationReply(ByteBuffer *bb)
	: optionSet(OptionSet::M_OP_REP)
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code = enumCast<SOCKS6OperationReplyCode>(rawOpReply->code);
	port = ntohs(rawOpReply->bindPort);
	initDataOff = ntohs(rawOpReply->initialDataOffset);
	
	address = Address(bb);
	
	optionSet = OptionSet(bb, OptionSet::M_OP_REP);
}

void OperationReply::pack(ByteBuffer *bb)
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	rawOpReply->code = code;
	rawOpReply->bindPort = htons(port);
	rawOpReply->initialDataOffset = htons(initDataOff);
	
	address.pack(bb);
	
	optionSet.pack(bb);
}

size_t OperationReply::packedSize()
{
	return sizeof(SOCKS6OperationReply) + address.packedSize() + optionSet.packedSize();
}

}
