#ifndef SOCKS6MSG_AUTHREPLY_HH
#define SOCKS6MSG_AUTHREPLY_HH

#include "bytebuffer.hh"
#include "optionset.hh"

namespace S6M
{

class AuthenticationReply
{
	SOCKS6AuthReplyCode replyCode;

public:	
	OptionSet options;

	AuthenticationReply(SOCKS6AuthReplyCode replyCode);
	
	AuthenticationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;
	
	SOCKS6AuthReplyCode getReplyCode() const
	{
		return replyCode;
	}
};

}

#endif // SOCKS6MSG_AUTHREPLY_HH
