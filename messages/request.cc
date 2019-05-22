#include "request.hh"
#include "version.hh"
#include "sanity.hh"

namespace S6M
{

Request::Request(ByteBuffer *bb)
	: optionSet(OptionSet::M_REQ)
{
	Version::check(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	commandCode = enumCast<SOCKS6RequestCode>(rawRequest->commandCode);
	port = ntohs(rawRequest->port);
	SOCKS6AddressType addrType = enumCast<SOCKS6AddressType>(rawRequest->addressType);
	
	address = Address(addrType, bb);
	
	optionSet = OptionSet(bb, OptionSet::M_REQ, ntohs(rawRequest->optionsLength));
}

void Request::pack(ByteBuffer *bb) const
{
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->version = SOCKS6_VERSION;
	rawRequest->commandCode = commandCode;
	rawRequest->optionsLength = htons(optionSet.packedSize());
	rawRequest->port = htons(port);
	rawRequest->padding = 0;
	
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
