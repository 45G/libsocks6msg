#include "authreply.hh"
#include "version.hh"
#include "sanity.hh"

namespace S6M
{

AuthenticationReply::AuthenticationReply(SOCKS6AuthReplyCode replyCode)
	: replyCode(replyCode), optionSet(OptionSet::M_AUTH_REP) {}

AuthenticationReply::AuthenticationReply(ByteBuffer *bb)
	: optionSet(OptionSet::M_AUTH_REP)
{
	Version::parse(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	replyCode = enumCast<SOCKS6AuthReplyCode>(rawAuthReply->type);
	
	optionSet = OptionSet(bb, OptionSet::M_AUTH_REP);
}

void AuthenticationReply::pack(ByteBuffer *bb) const
{
	Version::pack(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	rawAuthReply->type = replyCode;
	
	optionSet.pack(bb);
}

size_t AuthenticationReply::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t AuthenticationReply::packedSize() const
{
	return Version::packedSize() + sizeof (SOCKS6AuthReply) + optionSet.packedSize();
}

}
