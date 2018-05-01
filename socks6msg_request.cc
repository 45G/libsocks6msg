#include "socks6msg_request.hh"
#include "socks6msg_version.hh"

namespace S6M
{

Request::Request(SOCKS6RequestCode commandCode, Address address, uint16_t port, const OptionSet &optionSet, uint16_t initialDataLen)
	: commandCode(commandCode), address(address), port(port), optionSet(optionSet), initialDataLen(initialDataLen)
{
	switch (commandCode)
	{
	case SOCKS6_REQUEST_NOOP:
	case SOCKS6_REQUEST_CONNECT:
	case SOCKS6_REQUEST_BIND:
	case SOCKS6_REQUEST_UDP_ASSOC:
		break;
		
	default:
		throw InvalidFieldException();
	}
}

Request::Request(ByteBuffer *bb)
{
	Version ver(bb); (void)ver;
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	commandCode = (SOCKS6RequestCode)rawRequest->commandCode;
	port = ntohs(rawRequest->port);
	
	switch (commandCode)
	{
	case SOCKS6_REQUEST_NOOP:
	case SOCKS6_REQUEST_CONNECT:
	case SOCKS6_REQUEST_BIND:
	case SOCKS6_REQUEST_UDP_ASSOC:
		break;
		
	default:
		throw InvalidFieldException();
	}
	
	address = Address(bb);
	optionSet = OptionSet(bb);
	
	SOCKS6InitialData *rawInitialData = bb->get<SOCKS6InitialData>();
	initialDataLen = ntohs(rawInitialData->initialDataLen);
}

void Request::pack(ByteBuffer *bb)
{
	Version::pack(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->commandCode = commandCode;
	rawRequest->port = htons(port);
	
	address.pack(bb);
	
	optionSet.pack(bb);
		       
	SOCKS6InitialData *rawInitialData = bb->get<SOCKS6InitialData>();
	rawInitialData->initialDataLen = htons(initialDataLen);
}

size_t Request::packedSize()
{
	return Version::packedSize() + sizeof (SOCKS6Request) + address.packedSize() + optionSet.packedSize() + sizeof(SOCKS6InitialData);
}

}
