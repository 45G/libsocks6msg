#include "version.hh"
#include "exceptions.hh"

namespace S6M
{

void Version::parse(ByteBuffer *bb)
{
	/* parse byte-by-byte; other SOCKS versions don't have minors */
	uint8_t *version = bb->get<uint8_t>();
	if (*version != SOCKS6_VERSION)
		throw BadVersionException(*version);
}

void Version::pack(ByteBuffer *bb)
{
	SOCKS6Version *rawVer = bb->get<SOCKS6Version>();
	rawVer->version = SOCKS6_VERSION;
}

}
