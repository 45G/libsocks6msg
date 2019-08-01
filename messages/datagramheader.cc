#include "sanity.hh"
#include "version.hh"
#include "datagramheader.hh"


S6M::DatagramHeader::DatagramHeader(S6M::ByteBuffer *bb)
{
	Version::check(bb);

	SOCKS6DatagramHeader *rawHeader = bb->get<SOCKS6DatagramHeader>();
	assocID = be64toh(rawHeader->assocID);
	port = ntohs(rawHeader->port);
	SOCKS6AddressType addrType = enumCast<SOCKS6AddressType>(rawHeader->addressType);
	address = Address(addrType, bb);
}

void S6M::DatagramHeader::pack(S6M::ByteBuffer *bb) const
{
	SOCKS6DatagramHeader *rawHeader = bb->get<SOCKS6DatagramHeader>();
	rawHeader->version = SOCKS6_VERSION;
	rawHeader->addressType = address.getType();
	rawHeader->port = htons(port);
	rawHeader->assocID = htobe64(assocID);

	address.pack(bb);
}

size_t S6M::DatagramHeader::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t S6M::DatagramHeader::packedSize() const
{
	return sizeof(SOCKS6DatagramHeader) + address.packedSize();
}
