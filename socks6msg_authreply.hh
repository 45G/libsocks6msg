#ifndef SOCKS6MSG_AUTHREPLY_HH
#define SOCKS6MSG_AUTHREPLY_HH

#include "socks6msg_bytebuffer.hh"
#include "socks6msg_optionset.hh"

namespace S6M
{

class AuthenticationReply
{
	SOCKS6AuthReplyCode replyCode;
	
	SOCKS6Method method;
	
	OptionSet optionSet;
	
public:
	AuthenticationReply(SOCKS6AuthReplyCode replyCode, SOCKS6Method method);
	
	AuthenticationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize();
	
	SOCKS6AuthReplyCode getReplyCode() const
	{
		return replyCode;
	}
	
	SOCKS6Method getMethod() const
	{
		return method;
	}
	
	OptionSet *getOptionSet()
	{
		return &optionSet;
	}
	
};

}

#endif // SOCKS6MSG_AUTHREPLY_HH
