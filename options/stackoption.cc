#include <arpa/inet.h>
#include "stackoption.hh"
#include "../util/sanity.hh"
#include "optionset.hh"

namespace S6M
{

void StackOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6StackOption *opt = reinterpret_cast<SOCKS6StackOption *>(buf);
	
	opt->leg   = getLeg();
	opt->level = getLevel();
	opt->code  = getCode();
}

void StackOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (optionLen < sizeof(SOCKS6StackOption))
		throw InvalidFieldException();
	
	enumCast<SOCKS6StackLeg>(opt->leg);
	
	switch (opt->level)
	{
	case SOCKS6_STACK_LEVEL_IP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TOS:
			TOSOption::incementalParse(buf, optionLen, optionSet);
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
			TFOOption::incementalParse(buf, optionLen, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MPTCP:
			MPTCPOption::incementalParse(buf, optionLen, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MP_SCHED:
			MPSchedOption::incementalParse(buf, optionLen, optionSet);
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

	SOCKS6TOSOption *opt = reinterpret_cast<SOCKS6TOSOption *>(buf);

	opt->tos = tos;
}

size_t TOSOption::packedSize() const
{
	return sizeof(SOCKS6TOSOption);
}

void TOSOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6TOSOption *opt = (SOCKS6TOSOption *)buf;

	if (optionLen != sizeof(SOCKS6TOSOption))
		throw InvalidFieldException();

	uint8_t tos = opt->tos;

	switch (opt->stackOptionHead.leg)
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

void TFOOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6TFOOption *opt = (SOCKS6TFOOption *)buf;

	if (optionLen != sizeof(SOCKS6TFOOption))
		throw InvalidFieldException();
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw InvalidFieldException();

	uint16_t payloadSize = ntohs(opt->payloadLen);
	
	optionSet->setTFOPayload(payloadSize);
}

size_t MPTCPOption::packedSize() const
{
	return sizeof(SOCKS6StackOption);
}

void MPTCPOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = (SOCKS6StackOption *)buf;
	
	if (optionLen != sizeof(SOCKS6StackOption))
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

void MPSchedOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6MPTCPSchedulerOption *opt = (SOCKS6MPTCPSchedulerOption *)buf;
	
	if (optionLen != sizeof(SOCKS6MPTCPSchedulerOption))
		throw InvalidFieldException();
	
	SOCKS6MPTCPScheduler sched = enumCast<SOCKS6MPTCPScheduler>(opt->scheduler);
	
	switch (opt->stackOptionHead.leg)
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

void BacklogOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6BacklogOption *opt = (SOCKS6BacklogOption *)buf;

	if (optionLen != sizeof(SOCKS6BacklogOption))
		throw InvalidFieldException();

	uint8_t backlog = ntohs(opt->backlog);

	optionSet->setBacklog(backlog);
}

BacklogOption::BacklogOption(uint16_t backlog)
	: StackOption(SOCKS6_STACK_LEG_PROXY_REMOTE, SOCKS6_STACK_LEVEL_TCP, SOCKS6_STACK_CODE_BACKLOG), backlog(backlog)
{
	if (backlog < SOCKS6_BACKLOG_MIN)
		throw InvalidFieldException();
}

}
