#ifndef SOCKS6MSG_AUTHREPLY_HH
#define SOCKS6MSG_AUTHREPLY_HH

#include "socksmessagebase.hh"
#include "optionset.hh"

namespace S6M
{

struct AuthenticationReply: public SOCKSMessageBase<SOCKS6AuthReply>
{
	Enum<SOCKS6AuthReplyCode> code { SOCKS6_AUTH_REPLY_SUCCESS };

	OptionSet options { OptionSet::M_AUTH_REP };

	AuthenticationReply(SOCKS6AuthReplyCode replyCode)
		: code(replyCode) {}
	
	AuthenticationReply(ByteBuffer *bb)
		: SOCKSMessageBase(bb),
		  code(rawMessage->type),
		  options(bb, OptionSet::M_AUTH_REP, ntohs(rawMessage->optionsLength)) {}
	
	void pack(ByteBuffer *bb) const
	{
		SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
		
		rawAuthReply->version       = SOCKS6_VERSION;
		rawAuthReply->type          = code;
		rawAuthReply->optionsLength = htons(options.packedSize());
		
		options.pack(bb);
	}
	
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
