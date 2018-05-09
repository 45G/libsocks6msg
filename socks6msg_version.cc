#include "socks6msg_version.hh"

namespace S6M
{

Version::Version(ByteBuffer *bb)
{
	/* parse byte-by-byte; other SOCKS versions don't have minors */
	uint8_t *major = bb->get<uint8_t>();
	if (*major != SOCKS6_VERSION_MAJOR)
		throw BadVersionException(*major);
	
	uint8_t *minor = bb->get<uint8_t>();
	if (*minor != SOCKS6_VERSION_MINOR)
		throw BadVersionMinorException(*major, *minor);
}

void Version::pack(ByteBuffer *bb)
{
	SOCKS6Version *rawVer = bb->get<SOCKS6Version>();
	rawVer->major = SOCKS6_VERSION_MAJOR;
	rawVer->minor = SOCKS6_VERSION_MINOR;
}

}
