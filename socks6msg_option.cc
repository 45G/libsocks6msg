#include <arpa/inet.h>
#include <list>
#include <boost/foreach.hpp>
#include "socks6msg_option.hh"
#include "socks6msg_optionset.hh"
#include "socks6msg_sanity.hh"

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

void Option::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	
	switch (opt->kind) {
	case SOCKS6_OPTION_STACK:
		StackOption::parse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_METHOD:
		AuthMethodOption::parse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_DATA:
		AuthDataOption::parse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_IDEMPOTENCE:
		IdempotenceOption::parse(buf, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}
}

Option::~Option() {}

void StackOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
	SOCKS6StackOption *opt = reinterpret_cast<SOCKS6StackOption *>(buf);
	
	opt->leg = getLeg();
	opt->level = getLevel();
	opt->code = getCode();
}

void StackOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6StackOption))
		throw InvalidFieldException();
	
	enumCast<SOCKS6StackLeg>(opt->leg);
	
	switch (opt->level)
	{
//	case SOCKS6_SOCKOPT_LEVEL_SOCKET:
//		break;
		
//	case SOCKS6_SOCKOPT_LEVEL_IPV4:
//		break;
		
//	case SOCKS6_SOCKOPT_LEVEL_IPV6:
//		break;
		
	case SOCKS6_STACK_LEVEL_TCP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TFO:
			TFOOption::parse(buf, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MPTCP:
			MPTCPOption::parse(buf, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MP_SCHED:
			MPSchedOption::parse(buf, optionSet);
			break;
			
		default:
			throw InvalidFieldException();
		}
		break;
		
//	case SOCKS6_SOCKOPT_LEVEL_UDP:
//		break;
		
	default:
		throw InvalidFieldException();
	}
}

size_t TFOOption::packedSize() const
{
	return sizeof(SOCKS6StackOption);
}

void TFOOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->leg != SOCKS6_STACK_LEG_PROXY_SERVER)
		throw InvalidFieldException();
	
	optionSet->setTFO();
}

size_t MPTCPOption::packedSize() const
{
	return sizeof(SOCKS6StackOption);
}

void MPTCPOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->optionHead.len != sizeof(SOCKS6StackOption))
		throw InvalidFieldException();
	
	if (opt->leg != SOCKS6_STACK_LEG_PROXY_SERVER)
		throw InvalidFieldException();
	
	optionSet->setMPTCP();
}

size_t MPSchedOption::packedSize() const
{
	return sizeof(SOCKS6MPTCPSchedulerOption);
}

void MPSchedOption::forcedPack(uint8_t *buf) const
{
	StackOption::forcedPack(buf);
	
	SOCKS6MPTCPSchedulerOption *opt = reinterpret_cast<SOCKS6MPTCPSchedulerOption *>(buf);
	
	opt->scheduler = sched;
}

void MPSchedOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6MPTCPSchedulerOption *opt = (SOCKS6MPTCPSchedulerOption *)buf;
	
	if (opt->socketOptionHead.optionHead.len != sizeof(SOCKS6MPTCPSchedulerOption))
		throw InvalidFieldException();
	
	SOCKS6MPTCPScheduler sched = enumCast<SOCKS6MPTCPScheduler>(opt->scheduler);
	
	switch (opt->socketOptionHead.leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		optionSet->setClientProxySched(sched);
		break;
	case SOCKS6_STACK_LEG_PROXY_SERVER:
		optionSet->setProxyServerSched(sched);
		break;
	case SOCKS6_STACK_LEG_BOTH:
		optionSet->setBothScheds(sched);
		break;
	}
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

void AuthMethodOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthMethodOption *opt = (SOCKS6AuthMethodOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthMethodOption))
		throw InvalidFieldException();
	
	int methodCount = opt->optionHead.len - sizeof(SOCKS6AuthMethodOption);
	
	for (int i = 0; i < methodCount; i++)
		optionSet->advertiseMethod((SOCKS6Method)opt->methods[i]);
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

void AuthDataOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthDataOption))
		throw InvalidFieldException();
	
	switch (opt->method)
	{
	/* invalid, but handled by default */
//	case SOCKS6_METHOD_NOAUTH:
//	case SOCKS6_METHOD_UNACCEPTABLE:
//		throw InvalidFieldException();
		
	case SOCKS6_METHOD_USRPASSWD:
		UsernamePasswdOption::parse(buf, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}	
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

void UsernamePasswdOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	size_t expectedDataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		UserPasswordRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw InvalidFieldException();
		
		optionSet->attemptUserPasswdAuth(req.getUsername(), req.getPassword());
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

UsernamePasswdOption::UsernamePasswdOption(boost::shared_ptr<string> username, boost::shared_ptr<string> passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), req(username, passwd) {}

void IdempotenceOption::forcedPack(uint8_t *buf) const
{
	Option::forcedPack(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

void IdempotenceOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len < sizeof (SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		TokenWindowRequestOption::parse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		TokenWindowAdvertOption::parse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		TokenExpenditureRequestOption::parse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		TokenExpenditureReplyOption::parse(buf, optionSet);
		break;
	}
	
	throw InvalidFieldException();
}

size_t TokenWindowRequestOption::packedSize() const
{
	return sizeof(SOCKS6IdempotenceOption);
}

void TokenWindowRequestOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len != sizeof(SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	optionSet->requestTokenWindow();
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

void TokenWindowAdvertOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowAdvertOption))
		throw InvalidFieldException();
	
	uint32_t winBase = ntohl(opt->windowBase);
	uint32_t winSize = ntohl(opt->windowSize);
	
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	optionSet->advetiseTokenWindow(winBase, winSize);
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

void TokenExpenditureRequestOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureOption))
		throw InvalidFieldException();
	
	optionSet->spendToken(ntohl(opt->token));
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

void TokenExpenditureReplyOption::parse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw InvalidFieldException();
	
	optionSet->replyToExpenditure(enumCast<SOCKS6TokenExpenditureCode>(opt->code));
}

}
