#include "socks6msg_authreply.hh"
#include "socks6msg_version.hh"

namespace S6M
{

AuthenticationReply::AuthenticationReply(ByteBuffer *bb)
{
	Version ver(bb); (void)ver;
	
	SOCKS6AuthReply *rawAuthReply = bb->get<SOCKS6AuthReply>();
	replyCode = (SOCKS6AuthReplyCode)rawAuthReply->type;
	method  =(SOCKS6Method)rawAuthReply->method;
	
	switch (replyCode)
	{
	case SOCKS6_AUTH_REPLY_SUCCESS:
	case SOCKS6_AUTH_REPLY_MORE:
		break;
	
	default:
		throw Exception(S6M_ERR_INVALID);
	}
	
	/* be permissive with the method */
	
	optionSet = OptionSet(bb);
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
