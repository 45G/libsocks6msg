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

void StackOption::incrementalParse(SOCKS6Option *baseOpt, OptionSet *optionSet)
{
	SOCKS6StackOption *opt = rawOptCast<SOCKS6StackOption>(baseOpt);
	
	enumCast<SOCKS6StackLeg>(opt->leg);
	
	switch (opt->level)
	{
	case SOCKS6_STACK_LEVEL_IP:
		switch (opt->code)
		{
		case SOCKS6_STACK_CODE_TOS:
			TOSOption::incrementalParse(opt, optionSet);
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
			TFOOption::incrementalParse(opt, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_MP:
			MPTCPOption::incrementalParse(opt, optionSet);
			break;
			
		case SOCKS6_STACK_CODE_BACKLOG:
			BacklogOption::incrementalParse(opt, optionSet);
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

void TOSOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6TOSOption *opt = rawOptCast<SOCKS6TOSOption>(optBase, false);

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

void TFOOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6TFOOption *opt = rawOptCast<SOCKS6TFOOption>(optBase, false);
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");

	uint16_t payloadSize = ntohs(opt->payloadLen);
	
	optionSet->setTFOPayload(payloadSize);
}

void MPTCPOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6MPOption *opt = rawOptCast<SOCKS6MPOption>(optBase, false);
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");
	
	bool avail = opt->availability;
	
	if (avail)
		optionSet->setMPTCP();
}

void BacklogOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6BacklogOption *opt = rawOptCast<SOCKS6BacklogOption>(optBase, false);
	
	if (opt->stackOptionHead.leg != SOCKS6_STACK_LEG_PROXY_REMOTE)
		throw invalid_argument("Bad leg");

	uint8_t backlog = ntohs(opt->backlog);

	optionSet->setBacklog(backlog);
}

BacklogOption::BacklogOption(SOCKS6StackLeg leg, uint16_t backlog)
	: StackOptionBase(leg, backlog)
{
	if (backlog < SOCKS6_BACKLOG_MIN)
		throw invalid_argument("Bad backlog size");
}

}
