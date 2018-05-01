#include "socks6msg_opreply.hh"

namespace S6M
{

OperationReply::OperationReply(SOCKS6OperationReplyCode code, Address address, uint16_t port, uint16_t initDataOff, OptionSet optionSet)
	: code(code), address(address), port(port), initDataOff(initDataOff), optionSet(optionSet)
{
	switch (code)
	{
	case SOCKS6_OPERATION_REPLY_SUCCESS:
	case SOCKS6_OPERATION_REPLY_FAILURE:
	case SOCKS6_OPERATION_REPLY_NOT_ALLOWED:
	case SOCKS6_OPERATION_REPLY_NET_UNREACH:
	case SOCKS6_OPERATION_REPLY_HOST_UNREACH:
	case SOCKS6_OPERATION_REPLY_REFUSED:
	case SOCKS6_OPERATION_REPLY_TTL_EXPIRED:
	case SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED:
	case SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED:
		break;
		
	default:
		throw InvalidFieldException();
	}
}

OperationReply::OperationReply(ByteBuffer *bb)
{
	SOCKS6OperationReply *rawOpReply = bb->get<SOCKS6OperationReply>();
	
	code = (SOCKS6OperationReplyCode)rawOpReply->code;
	port = ntohs(rawOpReply->bindPort);
	initDataOff = ntohs(rawOpReply->initialDataOffset);
	
	address = Address(bb);
	
	optionSet = OptionSet(bb);
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
