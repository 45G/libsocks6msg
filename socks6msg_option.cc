#include <boost/foreach.hpp>
#include <list>
#include "socks6msg_option.hh"
#include "socks6msg.h"
#include "socks6msg_optionset.hh"

using namespace std;
using namespace boost;

namespace S6M
{

void Option::pack(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = getKind();
	opt->len = packedSize();
}

Option *Option::parse(void *buf)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	
	try
	{
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
	catch (Exception ex)
	{
		if (ex.getError() == S6M_ERR_INVALID)
			return RawOption::parse(buf);
		
		throw ex;
	}
}

Option::~Option() {}

size_t RawOption::packedSize() const
{
	return sizeof(SOCKS6Option) + data.size();
}

void RawOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	memcpy(opt->data, data.data(), data.size());	
}

Option *RawOption::parse(void *buf)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	size_t dataSize = opt->len - sizeof(SOCKS6Option);
	
	return new RawOption((SOCKS6OptionKind)opt->kind, opt->data, dataSize);
}

void RawOption::apply(OptionSet *optSet) const
{
	//TODO
}

RawOption::RawOption(SOCKS6OptionKind kind, uint8_t *data, size_t dataLen)
	: Option(kind)
{
	this->data.resize(dataLen);
	memcpy(this->data.data(), data, dataLen);
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

size_t TFOOption::packedSize() const
{
	return sizeof(SOCKS6SocketOption);
}

Option *TFOOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->leg != SOCKS6_SOCKOPT_LEG_PROXY_SERVER)
		throw Exception(S6M_ERR_INVALID);
	
	return new TFOOption();
}

void TFOOption::apply(OptionSet *optSet) const
{
	optSet->setTFO();
}

size_t MPTCPOption::packedSize() const
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

void MPTCPOption::apply(OptionSet *optSet) const
{
	optSet->setMPTCP();
}

size_t MPScehdOption::packedSize() const
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

void MPScehdOption::apply(OptionSet *optSet) const
{
	//TODO
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
	//TODO: really?
	if (sched == 0)
		throw Exception(S6M_ERR_INVALID);
}

size_t AuthMethodOption::packedSize() const
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
	SOCKS6AuthMethodOption *opt = (SOCKS6AuthMethodOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthMethodOption))
		throw Exception(S6M_ERR_INVALID);
	
	set<SOCKS6Method> methods;
	int methodCount = opt->optionHead.len - sizeof(SOCKS6AuthMethodOption);
	
	for (int i = 0; i < methodCount; i++)
	{
		if (opt->methods[i] == SOCKS6_METHOD_UNACCEPTABLE)
			throw Exception(S6M_ERR_INVALID);
		
		methods.insert((SOCKS6Method)opt->methods[i]);
	}
	
	return new AuthMethodOption(methods);
}

void AuthMethodOption::apply(OptionSet *optSet) const
{
	//TODO
}

AuthMethodOption::AuthMethodOption(std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw Exception(S6M_ERR_INVALID);
	if (methods.empty())
		throw Exception(S6M_ERR_INVALID);
}

void AuthDataOption::pack(uint8_t *buf) const
{
	Option::pack(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	opt->method = method;
}

Option *AuthDataOption::parse(void *buf)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthDataOption))
		throw Exception(S6M_ERR_INVALID);
	
	if (opt->method == SOCKS6_METHOD_NOAUTH || opt->method == SOCKS6_METHOD_UNACCEPTABLE)
		throw Exception(S6M_ERR_INVALID);
	
	if (opt->method == SOCKS6_METHOD_USRPASSWD)
	{
		try
		{
			return UsernamePasswdOption::parse(buf);
		}
		catch (Exception ex)
		{
			if (ex.getError() != S6M_ERR_INVALID)
				throw ex;
		}
	}
	
	return RawAuthDataOption::parse(buf);
}

size_t RawAuthDataOption::packedSize() const
{
	return sizeof(SOCKS6Option) + data.size() * sizeof(uint8_t);
}

void RawAuthDataOption::pack(uint8_t *buf) const
{
	AuthDataOption::pack(buf);
	
	SOCKS6AuthMethodOption *opt = reinterpret_cast<SOCKS6AuthMethodOption *>(buf);
	
	memcpy(opt->methods, data.data(), data.size());
}

Option *RawAuthDataOption::parse(void *buf)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	size_t dataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	return new RawAuthDataOption((SOCKS6Method)opt->method, opt->methodData, dataSize);
}

void RawAuthDataOption::apply(OptionSet *optSet) const
{
	//TODO
}

RawAuthDataOption::RawAuthDataOption(SOCKS6Method method, uint8_t *data, size_t dataLen)
	: AuthDataOption(method)
{
	this->data.resize(dataLen);
	memcpy(this->data.data(), data, dataLen);
}

size_t UsernamePasswdOption::packedSize() const
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
	ssize_t dataSize = S6M_PasswdReq_Pack(&pwReq, opt->methodData, packedSize() - sizeof(SOCKS6AuthDataOption), &err);
	if (dataSize == -1)
		throw Exception(err);
}

Option *UsernamePasswdOption::parse(void *buf)
{
	//TODO: use c++ implementation of passwd messages
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	S6M_Error err;
	S6M_PasswdReq *pwReq;
	
	size_t expectedDataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	ssize_t dataSize = S6M_PasswdReq_Parse((uint8_t *)(buf) + opt->optionHead.len, opt->optionHead.len - sizeof(SOCKS6AuthDataOption), &pwReq, &err);
	if (dataSize == -1)
		throw Exception(err);
	
	if ((size_t)dataSize != expectedDataSize)
	{
		S6M_PasswdReq_Free(pwReq);
		throw Exception(S6M_ERR_INVALID);
	}
	
	UsernamePasswdOption *ret = new UsernamePasswdOption(string(pwReq->username), string(pwReq->passwd));
	S6M_PasswdReq_Free(pwReq);
	
	return ret;	
}

void UsernamePasswdOption::apply(OptionSet *optSet) const
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
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len < sizeof (SOCKS6IdempotenceOption))
		throw Exception(S6M_ERR_INVALID);
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		return TokenWindowRequestOption::parse(buf);
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		return TokenWindowAdvertOption::parse(buf);
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		return TokenExpenditureRequestOption::parse(buf);
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		return TokenExpenditureReplyOption::parse(buf);
	}
	
	throw Exception(S6M_ERR_INVALID);
}

size_t TokenWindowRequestOption::packedSize() const
{
	return sizeof(SOCKS6IdempotenceOption);
}

Option *TokenWindowRequestOption::parse(void *buf)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len != sizeof(SOCKS6IdempotenceOption))
		throw Exception(S6M_ERR_INVALID);
	
	return new TokenWindowRequestOption();
}

void TokenWindowRequestOption::apply(OptionSet *optSet) const
{
	//TODO
}

size_t TokenWindowAdvertOption::packedSize() const
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
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowAdvertOption))
		throw Exception(S6M_ERR_INVALID);
	
	return new TokenWindowAdvertOption(ntohl(opt->windowBase), ntohl(opt->windowSize));
}

void TokenWindowAdvertOption::apply(OptionSet *optSet) const
{
	//TODO
}

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw Exception(S6M_ERR_INVALID);
}

size_t TokenExpenditureRequestOption::packedSize() const
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
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureOption))
		throw Exception(S6M_ERR_INVALID);
	
	return new TokenExpenditureRequestOption(ntohl(opt->token));
}

void TokenExpenditureRequestOption::apply(OptionSet *optSet) const
{
	//TODO
}

size_t TokenExpenditureReplyOption::packedSize() const
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
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw Exception(S6M_ERR_INVALID);
	
	switch ((SOCKS6TokenExpenditureCode)opt->code)
	{
	case SOCKS6_TOK_EXPEND_SUCCESS:
	case SOCKS6_TOK_EXPEND_NO_WND:
	case SOCKS6_TOK_EXPEND_OUT_OF_WND:
	case SOCKS6_TOK_EXPEND_DUPLICATE:
		break;
		
	default:
		throw Exception(S6M_ERR_INVALID);
	}
	
	return new TokenExpenditureReplyOption((SOCKS6TokenExpenditureCode)opt->code);
}

void TokenExpenditureReplyOption::apply(OptionSet *optSet) const
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

}
