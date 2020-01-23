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
	
	RAW *rawMessage = nullptr;
	
	MessageBase() {}
	
	MessageBase(ByteBuffer *bb)
		: versionChecker(bb), rawMessage(bb->get<RAW>()) {}
};

}

#endif // SOCKS6MSG_MESSAGEBASE_HH
