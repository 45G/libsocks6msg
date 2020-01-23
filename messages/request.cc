#include "request.hh"
#include "version.hh"
#include "sanity.hh"
#include "restrictedint.hh"

namespace S6M
{

Request::Request(ByteBuffer *bb)
{
	SOCKSVersion::check(bb);
	
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	
	code    = (SOCKS6RequestCode)rawRequest->commandCode;
	port    = ntohs(rawRequest->port);
	address = Address((SOCKS6AddressType)rawRequest->addressType, bb);
	options = OptionSet(bb, OptionSet::M_REQ, ntohs(rawRequest->optionsLength));
}

void Request::pack(ByteBuffer *bb) const
{
	SOCKS6Request *rawRequest = bb->get<SOCKS6Request>();
	
	rawRequest->version       = SOCKS6_VERSION;
	rawRequest->commandCode   = code;
	rawRequest->optionsLength = htons(options.packedSize());
	rawRequest->port          = htons(port);
	rawRequest->padding       = 0;
	rawRequest->addressType   = address.getType();
	
	address.pack(bb);
	options.pack(bb);
}

}
