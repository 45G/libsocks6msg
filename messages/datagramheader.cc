#include "sanity.hh"
#include "version.hh"
#include "datagramheader.hh"


S6M::DatagramHeader::DatagramHeader(S6M::ByteBuffer *bb)
{
	Version::check(bb);

	SOCKS6DatagramHeader *rawHeader = bb->get<SOCKS6DatagramHeader>();
	
	assocID = be64toh(rawHeader->assocID);
	port    = ntohs(rawHeader->port);
	address = Address((SOCKS6AddressType)rawHeader->addressType, bb);
}

void S6M::DatagramHeader::pack(S6M::ByteBuffer *bb) const
{
	SOCKS6DatagramHeader *rawHeader = bb->get<SOCKS6DatagramHeader>();
	
	rawHeader->version     = SOCKS6_VERSION;
	rawHeader->addressType = address.getType();
	rawHeader->port        = htons(port);
	rawHeader->assocID     = htobe64(assocID);

	address.pack(bb);
}
