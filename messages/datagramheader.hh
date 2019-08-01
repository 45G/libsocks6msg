#ifndef SOCKS6MSG_DATAGRAMHEADER_HH
#define SOCKS6MSG_DATAGRAMHEADER_HH

#include "bytebuffer.hh"
#include "address.hh"

namespace S6M
{

struct DatagramHeader
{
	uint64_t assocID;
	Address address;
	uint16_t port;

	DatagramHeader(uint64_t assocID, Address address = Address(), uint16_t port = 0)
		: assocID(assocID), address(address), port(port) {}

	DatagramHeader(ByteBuffer *bb);

	void pack(ByteBuffer *bb) const;

	size_t pack(uint8_t *buf, size_t bufSize) const;

	size_t packedSize() const;
};

}

#endif // SOCKS6MSG_DATAGRAMHEADER_HH
