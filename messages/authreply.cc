#include "authreply.hh"
#include "version.hh"
#include "sanity.hh"
#include "restrictedint.hh"

namespace S6M
{

AuthenticationReply::AuthenticationReply(SOCKS6AuthReplyCode replyCode)
	: replyCode(replyCode), options(OptionSet::M_AUTH_REP) {}

AuthenticationReply::AuthenticationReply(ByteBuffer *bb)
	: options(OptionSet::M_AUTH_REP)
{
	Version::check(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	replyCode = enumCast<SOCKS6AuthReplyCode>(rawAuthReply->type);
	
	OptionsLength optionsLength(ntohs(rawAuthReply->optionsLength));
	
	options = OptionSet(bb, OptionSet::M_AUTH_REP, optionsLength);
}

void AuthenticationReply::pack(ByteBuffer *bb) const
{
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	rawAuthReply->version = SOCKS6_VERSION;
	rawAuthReply->type = replyCode;
	rawAuthReply->optionsLength = htons(options.packedSize());
	
	options.pack(bb);
}

size_t AuthenticationReply::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t AuthenticationReply::packedSize() const
{
	return Version::packedSize() + sizeof (SOCKS6AuthReply) + options.packedSize();
}

}
