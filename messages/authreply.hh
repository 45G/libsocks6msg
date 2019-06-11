#ifndef SOCKS6MSG_AUTHREPLY_HH
#define SOCKS6MSG_AUTHREPLY_HH

#include "bytebuffer.hh"
#include "optionset.hh"

namespace S6M
{

class AuthenticationReply
{
	SOCKS6AuthReplyCode code;

public:	
	OptionSet options;

	AuthenticationReply(SOCKS6AuthReplyCode replyCode)
		: code(replyCode), options(OptionSet::M_AUTH_REP) {}
	
	AuthenticationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const;
	
	void setCode(SOCKS6AuthReplyCode code)
	{
		this->code = code;
	}

	SOCKS6AuthReplyCode getCode() const
	{
		return code;
	}
};

}

#endif // SOCKS6MSG_AUTHREPLY_HH
