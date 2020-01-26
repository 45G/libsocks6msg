#ifndef SOCKS6MSG_MESSAGEBASE_HH
#define SOCKS6MSG_MESSAGEBASE_HH

#include "socks6.h"
#include "versionchecker.hh"

namespace S6M
{

template<uint8_t VER, typename RAW>
class MessageBase
{
protected:
	VersionChecker<VER> versionChecker;
	
	static __thread RAW *rawMessage;
	
	MessageBase() {}
	
	/* not signal-safe */
	MessageBase(ByteBuffer *bb)
		: versionChecker(bb)
	{
		rawMessage = bb->get<RAW>();
	}
};

}

#endif // SOCKS6MSG_MESSAGEBASE_HH
