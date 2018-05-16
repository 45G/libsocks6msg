#include <arpa/inet.h>
#include <list>
#include <boost/foreach.hpp>
#include "socks6msg_option.hh"
#include "socks6msg_optionset.hh"

using namespace std;
using namespace boost;

namespace S6M
{

void Option::forcedPack(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = getKind();
	opt->len = packedSize();
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
	
	throw InvalidFieldException();
}

Option::~Option() {}

void SocketOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
	SOCKS6SocketOption *opt = reinterpret_cast<SOCKS6SocketOption *>(buf);
	
	opt->leg = getLeg();
	opt->level = getLevel();
	opt->code = getCode();
}

Option *SocketOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6SocketOption))
		throw InvalidFieldException();
	
	switch (opt->leg)
	{
	case SOCKS6_SOCKOPT_LEG_CLIENT_PROXY:
	case SOCKS6_SOCKOPT_LEG_PROXY_SERVER:
	case SOCKS6_SOCKOPT_LEG_BOTH:
		break;
		
	default:
		throw InvalidFieldException();
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
		throw InvalidFieldException();
	}
	
	throw InvalidFieldException();
}

size_t TFOOption::packedSize() const
{
	return sizeof(SOCKS6SocketOption);
}

Option *TFOOption::parse(void *buf)
{
	SOCKS6SocketOption *opt = (SOCKS6SocketOption *)buf;
	
	if (opt->leg != SOCKS6_SOCKOPT_LEG_PROXY_SERVER)
		throw InvalidFieldException();
	
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
		throw InvalidFieldException();
	
	if (opt->leg != SOCKS6_SOCKOPT_LEG_PROXY_SERVER)
		throw InvalidFieldException();
	
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

void MPScehdOption::forcedPack(uint8_t *buf) const
{
	SocketOption::forcedPack(buf);
	
	SOCKS6MPTCPSchedulerOption *opt = reinterpret_cast<SOCKS6MPTCPSchedulerOption *>(buf);
	
	opt->scheduler = sched;
}

Option *MPScehdOption::parse(void *buf)
{
	SOCKS6MPTCPSchedulerOption *opt = (SOCKS6MPTCPSchedulerOption *)buf;
	
	if (opt->socketOptionHead.optionHead.len != sizeof(SOCKS6MPTCPSchedulerOption))
		throw InvalidFieldException();
	
	/* be permissive with scheduler values */
	if (opt->scheduler == 0)
		throw InvalidFieldException();
	
	return new MPScehdOption((SOCKS6SocketOptionLeg)opt->socketOptionHead.leg, (SOCKS6MPTCPScheduler)opt->scheduler);
}

void MPScehdOption::apply(OptionSet *optSet) const
{
	switch (getLeg())
	{
	case SOCKS6_SOCKOPT_LEG_CLIENT_PROXY:
		optSet->setClientProxySched(sched);
		break;
	case SOCKS6_SOCKOPT_LEG_PROXY_SERVER:
		optSet->setProxyServerSched(sched);
		break;
	case SOCKS6_SOCKOPT_LEG_BOTH:
		optSet->setBothScheds(sched);
		break;
	}
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
		throw InvalidFieldException();
}

size_t AuthMethodOption::packedSize() const
{
	return sizeof(SOCKS6Option) + methods.size() * sizeof(uint8_t);
}

void AuthMethodOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
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
		throw InvalidFieldException();
	
	set<SOCKS6Method> methods;
	int methodCount = opt->optionHead.len - sizeof(SOCKS6AuthMethodOption);
	
	for (int i = 0; i < methodCount; i++)
	{
		if (opt->methods[i] == SOCKS6_METHOD_UNACCEPTABLE)
			throw InvalidFieldException();
		
		methods.insert((SOCKS6Method)opt->methods[i]);
	}
	
	return new AuthMethodOption(methods);
}

void AuthMethodOption::apply(OptionSet *optSet) const
{
	BOOST_FOREACH(SOCKS6Method method, methods)
	{
		optSet->advertiseMethod(method);
	}
}

AuthMethodOption::AuthMethodOption(std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw InvalidFieldException();
	if (methods.empty())
		throw InvalidFieldException();
}

void AuthDataOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	opt->method = method;
}

Option *AuthDataOption::parse(void *buf)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthDataOption))
		throw InvalidFieldException();
	
	if (opt->method == SOCKS6_METHOD_NOAUTH || opt->method == SOCKS6_METHOD_UNACCEPTABLE)
		throw InvalidFieldException();
	
	if (opt->method == SOCKS6_METHOD_USRPASSWD)
		return UsernamePasswdOption::parse(buf);

	throw InvalidFieldException();
}

size_t UsernamePasswdOption::packedSize() const
{
	return sizeof(SOCKS6AuthDataOption) + req.packedSize();
}

void UsernamePasswdOption::forcedPack(uint8_t *buf) const
{
	AuthDataOption::forcedPack(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	ByteBuffer bb(opt->methodData, opt->optionHead.len - sizeof(SOCKS6AuthDataOption));
	
	req.pack(&bb);
}

Option *UsernamePasswdOption::parse(void *buf)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	size_t expectedDataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		UserPasswordRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw InvalidFieldException();
		
		return new UsernamePasswdOption(req.getUsername(), req.getPassword());
	}
	catch (EndOfBufferException)
	{
		throw InvalidFieldException();
	}
	catch (BadVersionException)
	{
		throw InvalidFieldException();
	}
}

void UsernamePasswdOption::apply(OptionSet *optSet) const
{
	optSet->attemptUserPasswdAuth(req.getUsername(), req.getPassword());
}

UsernamePasswdOption::UsernamePasswdOption(string username, string passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), req(username, passwd) {}

void IdempotenceOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

Option *IdempotenceOption::parse(void *buf)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len < sizeof (SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
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
	
	throw InvalidFieldException();
}

size_t TokenWindowRequestOption::packedSize() const
{
	return sizeof(SOCKS6IdempotenceOption);
}

Option *TokenWindowRequestOption::parse(void *buf)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len != sizeof(SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	return new TokenWindowRequestOption();
}

void TokenWindowRequestOption::apply(OptionSet *optSet) const
{
	optSet->requestTokenWindow();
}

size_t TokenWindowAdvertOption::packedSize() const
{
	return sizeof(SOCKS6WindowAdvertOption);
}

void TokenWindowAdvertOption::forcedPack(uint8_t *buf) const
{
	IdempotenceOption::forcedPack(buf);
	
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	opt->windowBase = htonl(winBase);
	opt->windowSize = htonl(winSize);
}

Option *TokenWindowAdvertOption::parse(void *buf)
{
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowAdvertOption))
		throw InvalidFieldException();
	
	uint32_t winSize = ntohl(opt->windowSize);
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	return new TokenWindowAdvertOption(ntohl(opt->windowBase), winSize);
}

void TokenWindowAdvertOption::apply(OptionSet *optSet) const
{
	optSet->advetiseTokenWindow(winBase, winSize);
}

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
}

size_t TokenExpenditureRequestOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureOption);
}

void TokenExpenditureRequestOption::forcedPack(uint8_t *buf) const
{
	IdempotenceOption::forcedPack(buf);
	
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	opt->token = htonl(token);
}

Option *TokenExpenditureRequestOption::parse(void *buf)
{
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureOption))
		throw InvalidFieldException();
	
	return new TokenExpenditureRequestOption(ntohl(opt->token));
}

void TokenExpenditureRequestOption::apply(OptionSet *optSet) const
{
	optSet->spendToken(token);
}

size_t TokenExpenditureReplyOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureReplyOption);
}

void TokenExpenditureReplyOption::forcedPack(uint8_t *buf) const
{
	IdempotenceOption::forcedPack(buf);
	
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	opt->code = code;
}

Option *TokenExpenditureReplyOption::parse(void *buf)
{
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw InvalidFieldException();
	
	switch ((SOCKS6TokenExpenditureCode)opt->code)
	{
	case SOCKS6_TOK_EXPEND_SUCCESS:
	case SOCKS6_TOK_EXPEND_NO_WND:
	case SOCKS6_TOK_EXPEND_OUT_OF_WND:
	case SOCKS6_TOK_EXPEND_DUPLICATE:
		break;
		
	default:
		throw InvalidFieldException();
	}
	
	return new TokenExpenditureReplyOption((SOCKS6TokenExpenditureCode)opt->code);
}

void TokenExpenditureReplyOption::apply(OptionSet *optSet) const
{
	optSet->replyToExpenditure(code);
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
		throw InvalidFieldException();
	}
}

}
