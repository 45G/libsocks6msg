#ifndef SOCKS6MSG_MESSAGEBASE_HH
#define SOCKS6MSG_MESSAGEBASE_HH

#include "socks6.h"
#include "bytebuffer.hh"

namespace S6M
{

template<uint8_t VER, typename RAW>
class MessageBase
{
protected:
	RAW *rawMessage;
	
	MessageBase() {}
	
	MessageBase(ByteBuffer *bb)
	{
		uint8_t *ver = bb->peek<uint8_t>();
		if (*ver != VER)
			throw BadVersionException(*ver);
		
		rawMessage = bb->get<RAW>();
	}
};

}

#endif // SOCKS6MSG_MESSAGEBASE_HH
