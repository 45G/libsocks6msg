#include "socks6msg_version.hh"

namespace S6M
{

Version::Version(ByteBuffer *bb)
{
	uint8_t *major = bb->get<uint8_t>();
	if (*major != SOCKS6_VERSION_MAJOR)
		throw Exception(S6M_ERR_OTHERVER);
	
	uint8_t *minor = bb->get<uint8_t>();
	if (*minor != SOCKS6_VERSION_MINOR)
		throw Exception(S6M_ERR_OTHERVER);
}

void Version::pack(ByteBuffer *bb)
{
	uint8_t *major = bb->get<uint8_t>();
	*major = SOCKS6_VERSION_MAJOR;
	
	uint8_t *minor = bb->get<uint8_t>();
	*minor = SOCKS6_VERSION_MINOR;
}

}
