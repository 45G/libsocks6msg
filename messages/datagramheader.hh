#ifndef SOCKS6MSG_DATAGRAMHEADER_HH
#define SOCKS6MSG_DATAGRAMHEADER_HH

#include "socksmessagebase.hh"
#include "address.hh"

namespace S6M
{

struct DatagramHeader: public MessageBase<SOCKS6DatagramHeader>
{
	uint64_t assocID;
	Address  address;
	uint16_t port;

	DatagramHeader(uint64_t assocID, Address address = Address(), uint16_t port = 0)
		: assocID(assocID), address(address), port(port) {}

	DatagramHeader(ByteBuffer *bb)
		: MessageBase(bb),
		  assocID(be64toh(rawMessage->assocID)),
		  address((SOCKS6AddressType)rawMessage->addressType, bb),
		  port(ntohs(rawMessage->port)) {}

	void pack(ByteBuffer *bb) const
	{
		SOCKS6DatagramHeader *rawHeader = bb->get<SOCKS6DatagramHeader>();
		
		rawHeader->version     = SOCKS6_VERSION;
		rawHeader->addressType = address.getType();
		rawHeader->port        = htons(port);
		rawHeader->assocID     = htobe64(assocID);
		
		address.pack(bb);
	}

	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}

	size_t packedSize() const
	{
		return sizeof(SOCKS6DatagramHeader) + address.packedSize();
	}
};

}

#endif // SOCKS6MSG_DATAGRAMHEADER_HH
