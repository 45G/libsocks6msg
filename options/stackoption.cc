#include <arpa/inet.h>
#include "stackoption.hh"
#include "../util/sanity.hh"
#include "../socks6msg_optionset.hh"

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

}
