#ifndef SOCKS6MSG_VERSION_HH
#define SOCKS6MSG_VERSION_HH

#include "messagebase.hh"

namespace S6M
{

struct Version: public MessageBase<SOCKS6_VERSION, SOCKS6Version>
{
	Version() {}
	
	Version(ByteBuffer *bb)
		: MessageBase(bb) {}
	
	static size_t packedSize()
	{
		return sizeof(SOCKS6Version);
	}
	
	static void pack(ByteBuffer *bb)
	{
		SOCKS6Version *rawVer = bb->get<SOCKS6Version>();
		rawVer->version = SOCKS6_VERSION;
	}
	
	static size_t pack(uint8_t *buf, size_t bufSize)
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
};

}

#endif // SOCKS6MSG_VERSION_HH
