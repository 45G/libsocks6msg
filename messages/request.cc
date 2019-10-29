#include "request.hh"
#include "version.hh"
#include "sanity.hh"
#include "restrictedint.hh"

namespace S6M
{

Request::Request(ByteBuffer *bb)
{
	Version::check(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	code = enumCast<SOCKS6RequestCode>(rawRequest->commandCode);
	port = ntohs(rawRequest->port);
	SOCKS6AddressType addrType = enumCast<SOCKS6AddressType>(rawRequest->addressType);
	
	address = Address(addrType, bb);
	
	OptionsLength optionsLength(ntohs(rawRequest->optionsLength));
	
	options = OptionSet(bb, OptionSet::M_REQ, optionsLength);
}

void Request::pack(ByteBuffer *bb) const
{
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	rawRequest->version = SOCKS6_VERSION;
	rawRequest->commandCode = code;
	rawRequest->optionsLength = htons(options.packedSize());
	rawRequest->port = htons(port);
	rawRequest->padding = 0;
	rawRequest->addressType = address.getType();
	
	address.pack(bb);
	
	options.pack(bb);
}

size_t Request::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t Request::packedSize() const
{
	return sizeof(SOCKS6Request) + address.packedSize() + options.packedSize();
}

}
