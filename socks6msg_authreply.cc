#include "socks6msg_authreply.hh"
#include "socks6msg_version.hh"

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
	replyCode = (SOCKS6AuthReplyCode)rawAuthReply->type;
	method  = (SOCKS6Method)rawAuthReply->method;
	
	switch (replyCode)
	{
	case SOCKS6_AUTH_REPLY_SUCCESS:
	case SOCKS6_AUTH_REPLY_MORE:
		break;
	
	default:
		throw InvalidFieldException();
	}
	
	/* be permissive with the method */
	
	optionSet = OptionSet(bb, OptionSet::M_AUTH_REP);
}

void AuthenticationReply::pack(ByteBuffer *bb)
{
	Version::pack(bb);
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	rawAuthReply->type = replyCode;
	rawAuthReply->method = method;
	
	optionSet.pack(bb);
}

size_t AuthenticationReply::packedSize()
{
	return Version::packedSize() + sizeof (SOCKS6AuthReply) + optionSet.packedSize();
}

}
