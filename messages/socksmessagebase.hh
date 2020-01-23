#ifndef SOCKSMESSAGEBASE_HH
#define SOCKSMESSAGEBASE_HH

#include "socks6.h"
#include "versionchecker.hh"

namespace S6M
{

template<typename RAW>
class SOCKSMessageBase
{
protected:
	VersionChecker<SOCKS6_VERSION> versionChecker;
	
	RAW *rawMessage = nullptr;
	
	SOCKSMessageBase() {}
	
	SOCKSMessageBase(ByteBuffer *bb)
		: versionChecker(bb), rawMessage(bb->get<RAW>()) {}
};

}

#endif // SOCKSMESSAGEBASE_HH
