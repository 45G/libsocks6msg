#ifndef SOCKS6MSG_VERSION_HH
#define SOCKS6MSG_VERSION_HH

#include "socks6.h"
#include "bytebuffer.hh"

namespace S6M
{

struct Version
{
	static void check(ByteBuffer *bb);

	static void parse(ByteBuffer *bb);
	
	static size_t packedSize()
	{
		return sizeof(SOCKS6Version);
	}
	
	static void pack(ByteBuffer *bb);
};

}

#endif // SOCKS6MSG_VERSION_HH
