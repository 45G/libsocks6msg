#include "socks6msg_request.hh"
#include "socks6msg_version.hh"
#include "socks6msg_sanity.hh"

namespace S6M
{

Request::Request(SOCKS6RequestCode commandCode, Address address, uint16_t port, const OptionSet &optionSet, uint16_t initialDataLen)
	: commandCode(commandCode), address(address), port(port), optionSet(optionSet), initialDataLen(initialDataLen)
{
	if (optionSet.getMode() != OptionSet::M_REQ)
		throw InvalidFieldException();
}

Request::Request(ByteBuffer *bb)
	: optionSet(OptionSet::M_REQ)
{
	Version::parse(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	commandCode = enumCast<SOCKS6RequestCode>(rawRequest->commandCode);
	port = ntohs(rawRequest->port);
	
	address = Address(bb);
	optionSet = OptionSet(bb, OptionSet::M_REQ);
	
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
