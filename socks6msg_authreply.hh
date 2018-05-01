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
	AuthenticationReply(SOCKS6AuthReplyCode replyCode, SOCKS6Method method, OptionSet optionSet = OptionSet())
		: replyCode(replyCode), method(method), optionSet(optionSet) {}
	
	AuthenticationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
	
	size_t packedSize();
	
	SOCKS6AuthReplyCode getReplyCode() const
	{
		return replyCode;
	}
	
	SOCKS6Method getMethod() const
	{
		return method;
	}
	
	const OptionSet *getOptionSet() const
	{
		return &optionSet;
	}
	
};

}

#endif // SOCKS6MSG_AUTHREPLY_HH
