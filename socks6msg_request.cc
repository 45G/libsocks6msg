#include "socks6msg_request.hh"
#include "socks6msg_version.hh"
#include "util/sanity.hh"

namespace S6M
{

Request::Request(SOCKS6RequestCode commandCode, Address address, uint16_t port)
	: commandCode(commandCode), address(address), port(port), optionSet(OptionSet::M_REQ)
{
	if (address.getType() == Address::INVALID_TYPE)
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
}

void Request::pack(ByteBuffer *bb) const
{
	Version::pack(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->commandCode = commandCode;
	rawRequest->port = htons(port);
	
	address.pack(bb);
	
	optionSet.pack(bb);
}

size_t Request::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t Request::packedSize()
{
	return Version::packedSize() + sizeof (SOCKS6Request) + address.packedSize() + optionSet.packedSize();
}

}
