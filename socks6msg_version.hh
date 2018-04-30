#ifndef SOCKS6MSG_VERSION_HH
#define SOCKS6MSG_VERSION_HH

#include "socks6.h"
#include "socks6msg_bytebuffer.hh"

namespace S6M
{

class Version
{
public:
	Version() {}
	
	Version(ByteBuffer *bb);
	
	static size_t packedSize()
	{
		return sizeof(SOCKS6Version);
	}
	
	static void pack(ByteBuffer *bb);
};

}

#endif // SOCKS6MSG_VERSION_HH
