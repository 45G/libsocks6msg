#include "socks6msg_request.hh"

namespace S6M
{

Request::Request(SOCKS6RequestCode commandCode, Address addr, uint16_t port, const OptionSet &optionSet, uint16_t initialDataLen)
	: commandCode(commandCode), addr(addr), port(port), optionSet(optionSet), initialDataLen(initialDataLen)
{
	switch (commandCode)
	{
	case SOCKS6_REQUEST_NOOP:
	case SOCKS6_REQUEST_CONNECT:
	case SOCKS6_REQUEST_BIND:
	case SOCKS6_REQUEST_UDP_ASSOC:
		break;
		
	default:
		throw Exception(S6M_ERR_INVALID);
	}
}

Request *Request::parse(ByteBuffer *bb)
{
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->commandCode = commandCode;
	rawRequest->port = htons(port);
	
	Address *addr = Address::parse(bb);
	
	OptionSet *optionSet = OptionSet::parse(bb);
	
	SOCKS6InitialData *rawInitialData = bb->get<SOCKS6InitialData>();
	rawInitialData->initialDataLen = htons(initialDataLen);
}

void Request::pack(ByteBuffer *bb)
{
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->commandCode = commandCode;
	rawRequest->port = htons(port);
	
	addr.pack(bb);
	
	optionSet.pack(bb);
		       
	SOCKS6InitialData *rawInitialData = bb->get<SOCKS6InitialData>();
	rawInitialData->initialDataLen = htons(initialDataLen);
}

size_t Request::packedSize()
{
	return sizeof (SOCKS6Request) + addr.packedSize() + optionSet.packedSize() + sizeof(SOCKS6InitialData);
}

}
