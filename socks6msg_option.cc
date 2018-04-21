#include <boost/foreach.hpp>
#include "socks6msg_option.hh"
#include "socks6msg.h"

using namespace std;
using namespace boost;

namespace S6M
{

void Option::pack(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = getKind();
	opt->len = getLen();
}

Option *Option::parse(void *buf)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	
	switch (opt->kind) {
	case SOCKS6_OPTION_SOCKET:
		return SocketOption::parse(buf);
	case SOCKS6_OPTION_AUTH_METHOD:
		return AuthMethodOption::parse(buf);
	case SOCKS6_OPTION_AUTH_DATA:
		return AuthDataOption::parse(buf);
	case SOCKS6_OPTION_IDEMPOTENCE:
		return IdempotenceOption::parse(buf);
	}
	
	throw Exception(S6M_ERR_INVALID);
}

void SocketOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6SocketOption *opt = reinterpret_cast<SOCKS6SocketOption *>(buf);
	
	opt->leg = getLeg();
	opt->level = getLevel();
	opt->code = getCode();
}

Option *SocketOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->optionHead.len < sizeof(SocketOption))
		throw Exception(S6M_ERR_INVALID);
	
	switch (opt->leg)
	{
	case SOCKS6_SOCKOPT_LEG_CLIENT_PROXY:
	case SOCKS6_SOCKOPT_LEG_PROXY_SERVER:
	case SOCKS6_SOCKOPT_LEG_BOTH:
		break;
		
	default:
		throw Exception(S6M_ERR_INVALID);
	}
	
	switch (opt->level)
	{
	case SOCKS6_SOCKOPT_LEVEL_SOCKET:
		break;
		
	case SOCKS6_SOCKOPT_LEVEL_IPV4:
		break;
		
	case SOCKS6_SOCKOPT_LEVEL_IPV6:
		break;
		
	case SOCKS6_SOCKOPT_LEVEL_TCP:
		switch (opt->code)
		{
		case SOCKS6_SOCKOPT_CODE_TFO:
			return TFOOption::parse(buf);
			
		case SOCKS6_SOCKOPT_CODE_MPTCP:
			return MPTCPOption::parse(buf);
			
		case SOCKS6_SOCKOPT_CODE_MP_SCHED:
			return MPScehdOption::parse(buf);
		}
		break;
		
	case SOCKS6_SOCKOPT_LEVEL_UDP:
		break;
	default:
		throw Exception(S6M_ERR_INVALID);
	}
	
	throw Exception(S6M_ERR_INVALID);
}

size_t TFOOption::getLen() const
{
	return sizeof(SOCKS6SocketOption);
}

Option *TFOOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->optionHead.len != sizeof(SOCKS6SocketOption))
		throw Exception(S6M_ERR_INVALID);
	
	if (opt->leg != SOCKS6_SOCKOPT_LEG_PROXY_SERVER)
		throw Exception(S6M_ERR_INVALID);
	
	return new TFOOption();
}

size_t MPTCPOption::getLen() const
{
	return sizeof(SOCKS6SocketOption);
}

Option *MPTCPOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->optionHead.len != sizeof(SOCKS6SocketOption))
		throw Exception(S6M_ERR_INVALID);
	
	if (opt->leg != SOCKS6_SOCKOPT_LEG_PROXY_SERVER)
		throw Exception(S6M_ERR_INVALID);
	
	return new MPTCPOption();
}

size_t MPScehdOption::getLen() const
{
	return sizeof(SOCKS6MPTCPSchedulerOption);
}

void MPScehdOption::pack(uint8_t *buf) const
{
	SocketOption::pack(buf);
	
	SOCKS6MPTCPSchedulerOption *opt = reinterpret_cast<SOCKS6MPTCPSchedulerOption *>(buf);
	
	opt->scheduler = sched;
}

Option *MPScehdOption::parse(void *buf)
{
	SOCKS6MPTCPSchedulerOption *opt = (SOCKS6MPTCPSchedulerOption *)buf;
	
	if (opt->socketOptionHead.optionHead.len != sizeof(SOCKS6MPTCPSchedulerOption))
		throw Exception(S6M_ERR_INVALID);
	
	/* be permissive with scheduler values */
	if (opt->scheduler == 0)
		throw Exception(S6M_ERR_INVALID);
	
	return new MPScehdOption((SOCKS6SocketOptionLeg)opt->socketOptionHead.leg, (SOCKS6MPTCPScheduler)opt->scheduler);
}

MPScehdOption::MPScehdOption(SOCKS6SocketOptionLeg leg, SOCKS6MPTCPScheduler sched)
	: SocketOption(leg, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_MP_SCHED), sched(sched)
{
//	switch (sched)
//	{
//	case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
//	case SOCKS6_MPTCP_SCHEDULER_RR:
//	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
//		break;
		
//	default:
//		throw Exception(S6M_ERR_INVALID);
//	}
	
	/* be permissive with scheduler values */
	if (sched == 0)
		throw Exception(S6M_ERR_INVALID);
}

size_t AuthMethodOption::getLen() const
{
	return sizeof(SOCKS6Option) + methods.size() * sizeof(uint8_t);
}

void AuthMethodOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6AuthMethodOption *opt = reinterpret_cast<SOCKS6AuthMethodOption *>(buf);
	
	int i = 0;
	BOOST_FOREACH(SOCKS6Method method, methods)
	{
		opt->methods[i] = method;
	}
}

Option *AuthMethodOption::parse(void *buf)
{
	//TODOX
}

AuthMethodOption::AuthMethodOption(std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw Exception(S6M_ERR_INVALID);
	if (methods.empty())
		throw Exception(S6M_ERR_INVALID);
}

Option *AuthDataOption::parse(void *buf)
{
	//TODOX
}

size_t RawAuthDataOption::getLen() const
{
	return sizeof(SOCKS6Option) + data.size() * sizeof(uint8_t);
}

void RawAuthDataOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6AuthMethodOption *opt = reinterpret_cast<SOCKS6AuthMethodOption *>(buf);
	
	memcpy(opt->methods, data.data(), data.size());
}

Option *RawAuthDataOption::parse(void *buf)
{
	//TODO
}

size_t UsernamePasswdOption::getLen() const
{
	const S6M_PasswdReq pwReq = {
		.username = username.c_str(),
		.passwd = passwd.c_str(),
	};
	
	S6M_Error err;
	ssize_t dataSize = S6M_PasswdReq_Packed_Size(&pwReq, &err);
	if (dataSize == -1)
		throw Exception(err);
	
	return sizeof(AuthDataOption) + dataSize;
}

void UsernamePasswdOption::pack(uint8_t *buf) const
{
	AuthDataOption::pack(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	S6M_PasswdReq pwReq = {
		.username = username.c_str(),
		.passwd = passwd.c_str(),
	};
	
	S6M_Error err;
	ssize_t dataSize = S6M_PasswdReq_Pack(&pwReq, opt->methodData, getLen() - sizeof(SOCKS6AuthDataOption), &err);
	if (dataSize == -1)
		throw Exception(err);
}

Option *UsernamePasswdOption::parse(void *buf)
{
	//TODO
}

UsernamePasswdOption::UsernamePasswdOption(string username, string passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), username(username), passwd(passwd) {}

void IdempotenceOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

Option *IdempotenceOption::parse(void *buf)
{
	//TODOX
}

size_t TokenWindowRequestOption::getLen() const
{
	return sizeof(SOCKS6IdempotenceOption);
}

Option *TokenWindowRequestOption::parse(void *buf)
{
	//TODO
}

size_t TokenWindowAdvertOption::getLen() const
{
	return sizeof(SOCKS6WindowAdvertOption);
}

void TokenWindowAdvertOption::pack(uint8_t *buf) const
{
	IdempotenceOption::pack(buf);
	
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	opt->windowBase = htonl(winBase);
	opt->windowSize = htonl(winSize);
}

Option *TokenWindowAdvertOption::parse(void *buf)
{
	//TODO
}

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw Exception(S6M_ERR_INVALID);
}

size_t TokenExpenditureRequestOption::getLen() const
{
	return sizeof(SOCKS6TokenExpenditureOption);
}

void TokenExpenditureRequestOption::pack(uint8_t *buf) const
{
	IdempotenceOption::pack(buf);
	
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	opt->token = htonl(token);
}

Option *TokenExpenditureRequestOption::parse(void *buf)
{
	//TODO
}

size_t TokenExpenditureReplyOption::getLen() const
{
	return sizeof(SOCKS6TokenExpenditureReplyOption);
}

void TokenExpenditureReplyOption::pack(uint8_t *buf) const
{
	IdempotenceOption::pack(buf);
	
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	opt->code = code;
}

Option *TokenExpenditureReplyOption::parse(void *buf)
{
	//TODO
}

TokenExpenditureReplyOption::TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY), code(code)
{
	switch (code)
	{
	case SOCKS6_TOK_EXPEND_SUCCESS:
	case SOCKS6_TOK_EXPEND_NO_WND:
	case SOCKS6_TOK_EXPEND_OUT_OF_WND:
	case SOCKS6_TOK_EXPEND_DUPLICATE:
		break;
		
	default:
		throw Exception(S6M_ERR_INVALID);
	}
}

Option *parseOption(ByteBuffer *bb)
{
	SOCKS6Option *opt = bb->get<SOCKS6Option>();
	
	if (opt->len < 2)
		throw Exception(S6M_ERR_INVALID);
	
	bb->get<uint8_t>(opt->len - sizeof(SOCKS6Option));
	
	return Option::parse(opt);
}

}
