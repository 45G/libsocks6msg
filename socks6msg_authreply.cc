#include "socks6msg_authreply.hh"
#include "socks6msg_version.hh"
#include "socks6msg_sanity.hh"

namespace S6M
{

AuthenticationReply::AuthenticationReply(SOCKS6AuthReplyCode replyCode, SOCKS6Method method, OptionSet optionSet)
	: replyCode(replyCode), method(method), optionSet(optionSet)
{
	if (optionSet.getMode() != OptionSet::M_AUTH_REP)
		throw InvalidFieldException();
}

AuthenticationReply::AuthenticationReply(ByteBuffer *bb)
	: optionSet(OptionSet::M_AUTH_REP)
{
	Version::parse(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	replyCode = enumCast<SOCKS6AuthReplyCode>(rawAuthReply->type);
	/* be permissive with the method */
	method  = (SOCKS6Method)rawAuthReply->method;
	
	optionSet = OptionSet(bb, OptionSet::M_AUTH_REP);
}

void AuthenticationReply::pack(ByteBuffer *bb) const
{
	Version::pack(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	rawAuthReply->type = replyCode;
	rawAuthReply->method = method;
	
	optionSet.pack(bb);
}

size_t AuthenticationReply::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

size_t AuthenticationReply::packedSize()
{
	return Version::packedSize() + sizeof (SOCKS6AuthReply) + optionSet.packedSize();
}

}
