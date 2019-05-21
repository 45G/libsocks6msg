#include "version.hh"
#include "exceptions.hh"

namespace S6M
{

void Version::check(ByteBuffer *bb)
{
	SOCKS6Version *rawVer = bb->peek<SOCKS6Version>();
	if (rawVer->version != SOCKS6_VERSION)
		throw BadVersionException(rawVer->version);
}

void Version::parse(ByteBuffer *bb)
{
	SOCKS6Version *rawVer = bb->get<SOCKS6Version>();
	if (rawVer->version != SOCKS6_VERSION)
		throw BadVersionException(rawVer->version);
}

void Version::pack(ByteBuffer *bb)
{
	SOCKS6Version *rawVer = bb->get<SOCKS6Version>();
	rawVer->version = SOCKS6_VERSION;
}

}
