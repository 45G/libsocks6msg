#include <arpa/inet.h>
#include "stackoption.hh"
#include "sanity.hh"
#include "optionset.hh"

using namespace std;

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
	SOCKS6StackOption *opt = rawOptCast<SOCKS6StackOption>(buf);
	
	enumCast<SOCKS6StackLeg>(opt->leg);
	
	switch (opt->level)
	{
	case SOCKS6_STACK_LEVEL_IP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TOS:
			TOSOption::incementalParse(buf, optionSet);
			break;
		default:
			throw invalid_argument("Unknown code");
		}
		break;
		
	case SOCKS6_STACK_LEVEL_IPV4:
		throw invalid_argument("Unknown code");
		
	case SOCKS6_STACK_LEVEL_IPV6:
		throw invalid_argument("Unknown code");
		
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
			throw invalid_argument("Unknown code");
		}
		break;
		
	case SOCKS6_STACK_LEVEL_UDP:
		throw invalid_argument("Unknown code");
		
	default:
		throw invalid_argument("Bad stack level");
	}
}

void TOSOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TOSOption *opt = rawOptCast<SOCKS6TOSOption>(buf, false);

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

void TFOOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TFOOption *opt = rawOptCast<SOCKS6TFOOption>(buf, false);
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");

	uint16_t payloadSize = ntohs(opt->payloadLen);
	
	optionSet->setTFOPayload(payloadSize);
}

void MPTCPOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = rawOptCast<SOCKS6StackOption>(buf, false);
	
	if (opt->leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");
	
	optionSet->setMPTCP();
}

void MPSchedOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6MPTCPSchedulerOption *opt = rawOptCast<SOCKS6MPTCPSchedulerOption>(buf, false);
	
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

void BacklogOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6BacklogOption *opt = rawOptCast<SOCKS6BacklogOption>(buf, false);
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");

	uint8_t backlog = ntohs(opt->backlog);

	optionSet->setBacklog(backlog);
}

BacklogOption::BacklogOption(uint16_t backlog)
	: IntStackOptionBase(SOCKS6_STACK_LEG_PROXY_REMOTE, backlog)
{
	if (backlog < SOCKS6_BACKLOG_MIN)
		throw invalid_argument("Bad backlog size");
}

}
