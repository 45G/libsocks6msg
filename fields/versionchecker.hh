#ifndef SOCKS6MSG_VERSIONCHECKER_HH
#define SOCKS6MSG_VERSIONCHECKER_HH

#include "bytebuffer.hh"

namespace S6M
{

template <uint8_t VER>
struct VersionChecker
{
	VersionChecker() {}
	
	VersionChecker(ByteBuffer *bb)
	{
		uint8_t *ver = bb->peek<uint8_t>();
		if (*ver != VER)
			throw BadVersionException(*ver);
	}
};

}

#endif // SOCKS6MSG_VERSIONCHECKER_HH
