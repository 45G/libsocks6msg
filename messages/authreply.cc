#include "authreply.hh"
#include "version.hh"
#include "sanity.hh"
#include "restrictedint.hh"

namespace S6M
{

AuthenticationReply::AuthenticationReply(ByteBuffer *bb)
{
	Version::check(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	code = enumCast<SOCKS6AuthReplyCode>(rawAuthReply->type);
	
	options = OptionSet(bb, OptionSet::M_AUTH_REP, ntohs(rawAuthReply->optionsLength));
}

void AuthenticationReply::pack(ByteBuffer *bb) const
{
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	rawAuthReply->version = SOCKS6_VERSION;
	rawAuthReply->type = code;
	rawAuthReply->optionsLength = htons(options.packedSize());
	
	options.pack(bb);
}

}
