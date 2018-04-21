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

void SocketOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6SocketOption *opt = reinterpret_cast<SOCKS6SocketOption *>(buf);
	
	opt->leg = getLeg();
	opt->level = getLevel();static const size_t VER_SIZE = 1;
	opt->code = getCode();
}

size_t TFOOption::getLen() const
{
	return sizeof(SOCKS6SocketOption);
}

size_t MPTCPOption::getLen() const
{
	return sizeof(SOCKS6SocketOption);
}

void MPScehdOption::pack(uint8_t *buf) const
{
	SocketOption::pack(buf);
	
	SOCKS6MPTCPSchedulerOption *opt = reinterpret_cast<SOCKS6MPTCPSchedulerOption *>(buf);
	
	opt->scheduler = sched;
}

MPScehdOption::MPScehdOption(SOCKS6SocketOptionLeg leg, SOCKS6MPTCPScheduler sched)
	: SocketOption(leg, SOCKS6_SOCKOPT_LEVEL_TCP, SOCKS6_SOCKOPT_CODE_MP_SCHED), sched(sched)
{
	switch (sched)
	{
	case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
	case SOCKS6_MPTCP_SCHEDULER_RR:
	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		break;
		
	default:
		throw Exception(S6M_ERR_INVALID);
	}
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

AuthMethodOption::AuthMethodOption(std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw Exception(S6M_ERR_INVALID);
	if (methods.empty())
		throw Exception(S6M_ERR_INVALID);
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

size_t UsernamePasswdOption::getLen() const
{
	S6M_PasswdReq pwReq = {
		.username = username.c_str(),
		.passwd = passwd.c_str(),
	};
	
	S6M_Error err;
	ssize_t dataSize = S6M_PasswdReq_Packed_Size(&pwReq, err);
	if (dataSize == -1)
		throw Exception(err);
	
	return sizeof(AuthDataOption) + dataSize;
}

UsernamePasswdOption::UsernamePasswdOption(string username, string passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), username(username), passwd(passwd) {}

void IdempotenceOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption>(buf);
	
	opt->type = type;
}

size_t TokenWindowRequestOption::getLen() const
{
	return sizeof(SOCKS6IdempotenceOption);
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

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	//TODO: move to socks6.h
	static const size_t MIN_WIN = 1;
	static const size_t MAX_WIN = (1UL << 31) - 1;
	
	if (winSize < MIN_WIN || winSize > MAX_WIN)
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

}
