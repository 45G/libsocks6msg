#include "request.hh"
#include "version.hh"
#include "sanity.hh"

namespace S6M
{

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

size_t Request::packedSize() const
{
	return Version::packedSize() + sizeof (SOCKS6Request) + address.packedSize() + optionSet.packedSize();
}

}
