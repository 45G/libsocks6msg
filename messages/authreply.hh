#ifndef SOCKS6MSG_AUTHREPLY_HH
#define SOCKS6MSG_AUTHREPLY_HH

#include "bytebuffer.hh"
#include "optionset.hh"

namespace S6M
{

struct AuthenticationReply
{
	SOCKS6AuthReplyCode code;

	OptionSet options { OptionSet::M_AUTH_REP };

	AuthenticationReply(SOCKS6AuthReplyCode replyCode)
		: code(replyCode) {}
	
	AuthenticationReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
	
	size_t packedSize() const
	{
		return sizeof(SOCKS6AuthReply) + options.packedSize();
	}
};

}

#endif // SOCKS6MSG_AUTHREPLY_HH
