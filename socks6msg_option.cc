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

void Option::fill(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = getKind();
	opt->len  = packedSize();
}

void Option::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	
	switch (opt->kind) {
	case SOCKS6_OPTION_STACK:
		StackOption::incementalParse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_METHOD:
		AuthMethodOption::incementalParse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_DATA:
		AuthDataOption::incementalParse(buf, optionSet);
		break;
		
	case SOCKS6_OPTION_IDEMPOTENCE:
		IdempotenceOption::incementalParse(buf, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}
}

Option::~Option() {}

void StackOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6StackOption *opt = reinterpret_cast<SOCKS6StackOption *>(buf);
	
	opt->leg   = getLeg();
	opt->level = getLevel();
	opt->code  = getCode();
}

void StackOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6StackOption))
		throw InvalidFieldException();
	
	enumCast<SOCKS6StackLeg>(opt->leg);
	
	switch (opt->level)
	{
	case SOCKS6_STACK_LEVEL_IP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TOS:
			TOSOption::incementalParse(buf, optionSet);
			break;
		}
		break;
		
//	case SOCKS6_STACK_LEVEL_IPV4:
//		break;
		
//	case SOCKS6_STACK_LEVEL_IPV6:
//		break;
		
	case SOCKS6_STACK_LEVEL_TCP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TFO:
			TFOOption::incementalParse(buf, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MPTCP:
			MPTCPOption::incementalParse(buf, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MP_SCHED:
			MPSchedOption::incementalParse(buf, optionSet);
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

void TOSOption::fill(uint8_t *buf) const
{
	StackOption::fill(buf);

	TOSOption *opt = reinterpret_cast<TOSOption *>(buf);

	opt->tos = tos;
}

size_t TOSOption::packedSize() const
{
	return sizeof(SOCKS6TOSOption);
}

void TOSOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TOSOption *opt = (SOCKS6TOSOption *)buf;

	if (opt->socketOptionHead.optionHead.len != sizeof(SOCKS6TOSOption))
		throw InvalidFieldException();

	uint8_t tos = opt->tos;

	switch (opt->socketOptionHead.leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		optionSet->setClientProxyTOS(tos);
		break;
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		optionSet->setProxyRemoteTOS(tos);
		break;
	case SOCKS6_STACK_LEG_BOTH:
		optionSet->setBothTOS(tos);
		break;
	}
}

size_t TFOOption::packedSize() const
{
	return sizeof(SOCKS6StackOption);
}

void TFOOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw InvalidFieldException();
	
	optionSet->setTFO();
}

size_t MPTCPOption::packedSize() const
{
	return sizeof(SOCKS6StackOption);
}

void MPTCPOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (opt->optionHead.len != sizeof(SOCKS6StackOption))
		throw InvalidFieldException();
	
	if (opt->leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw InvalidFieldException();
	
	optionSet->setMPTCP();
}

size_t MPSchedOption::packedSize() const
{
	return sizeof(SOCKS6MPTCPSchedulerOption);
}

void MPSchedOption::fill(uint8_t *buf) const
{
	StackOption::fill(buf);
	
	SOCKS6MPTCPSchedulerOption *opt = reinterpret_cast<SOCKS6MPTCPSchedulerOption *>(buf);
	
	opt->scheduler = sched;
}

void MPSchedOption::incementalParse(void *buf, OptionSet *optionSet)
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
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		optionSet->setProxyRemoteSched(sched);
		break;
	case SOCKS6_STACK_LEG_BOTH:
		optionSet->setBothScheds(sched);
		break;
	}
}

void BacklogOption::fill(uint8_t *buf) const
{
	StackOption::fill(buf);

	SOCKS6BacklogOption *opt = reinterpret_cast<SOCKS6BacklogOption *>(buf);

	opt->backlog = htons(backlog);
}

size_t BacklogOption::packedSize() const
{
	return sizeof(SOCKS6BacklogOption);
}

void BacklogOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6BacklogOption *opt = (SOCKS6BacklogOption *)buf;

	if (opt->socketOptionHead.optionHead.len != sizeof(SOCKS6BacklogOption))
		throw InvalidFieldException();

	uint8_t backlog = ntohs(opt->backlog);

	optionSet->setBacklog(backlog);
}

size_t AuthMethodOption::packedSize() const
{
	return sizeof(SOCKS6Option) + methods.size() * sizeof(uint8_t);
}

void AuthMethodOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthMethodOption *opt = reinterpret_cast<SOCKS6AuthMethodOption *>(buf);
	
	int i = 0;
	BOOST_FOREACH(SOCKS6Method method, methods)
	{
		opt->methods[i] = method;
	}
}

void AuthMethodOption::incementalParse(void *buf, OptionSet *optionSet)
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

void AuthDataOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	opt->method = method;
}

void AuthDataOption::incementalParse(void *buf, OptionSet *optionSet)
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
		UsernamePasswdOption::incementalParse(buf, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}	
}

size_t UsernamePasswdOption::packedSize() const
{
	return sizeof(SOCKS6AuthDataOption) + req.packedSize();
}

void UsernamePasswdOption::fill(uint8_t *buf) const
{
	AuthDataOption::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	ByteBuffer bb(opt->methodData, opt->optionHead.len - sizeof(SOCKS6AuthDataOption));
	
	req.pack(&bb);
}

void UsernamePasswdOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	size_t expectedDataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		UserPasswordRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw InvalidFieldException();
		
		optionSet->setUsernamePassword(req.getUsername(), req.getPassword());
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

void IdempotenceOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

void IdempotenceOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len < sizeof (SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		TokenWindowRequestOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		TokenWindowAdvertOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		TokenExpenditureRequestOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		TokenExpenditureReplyOption::incementalParse(buf, optionSet);
		break;
	}
	
	throw InvalidFieldException();
}

void TokenWindowRequestOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	opt->windowSize = htonl(winSize);
}

size_t TokenWindowRequestOption::packedSize() const
{
	return sizeof(SOCKS6WindowRequestOption);
}

void TokenWindowRequestOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowRequestOption))
		throw InvalidFieldException();
	
	uint32_t winSize = ntohl(opt->windowSize);
	
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	optionSet->requestTokenWindow(winSize);
}

TokenWindowRequestOption::TokenWindowRequestOption(uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_REQ), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
}

size_t TokenWindowAdvertOption::packedSize() const
{
	return sizeof(SOCKS6WindowAdvertOption);
}

void TokenWindowAdvertOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	opt->windowBase = htonl(winBase);
	opt->windowSize = htonl(winSize);
}

void TokenWindowAdvertOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowAdvertOption))
		throw InvalidFieldException();
	
	uint32_t winBase = ntohl(opt->windowBase);
	uint32_t winSize = ntohl(opt->windowSize);
	
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	optionSet->setTokenWindow(winBase, winSize);
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

void TokenExpenditureRequestOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	opt->token = htonl(token);
}

void TokenExpenditureRequestOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureOption))
		throw InvalidFieldException();
	
	optionSet->setToken(ntohl(opt->token));
}

size_t TokenExpenditureReplyOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureReplyOption);
}

void TokenExpenditureReplyOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	opt->code = code;
}

void TokenExpenditureReplyOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw InvalidFieldException();
	
	optionSet->setExpenditureReply(enumCast<SOCKS6TokenExpenditureCode>(opt->code));
}

}
