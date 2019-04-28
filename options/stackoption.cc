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
	SOCKS6StackLeg leg = (SOCKS6StackLeg)opt->stackOptionHead.leg;

	optionSet->stack()->tos()->set(leg, opt->tos);
}

void TFOOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6TFOOption *opt = rawOptCast<SOCKS6TFOOption>(optBase, false);
	SOCKS6StackLeg leg = (SOCKS6StackLeg)opt->stackOptionHead.leg;
	uint16_t payloadSize = ntohs(opt->payloadLen);
	
	optionSet->stack()->tfo()->set(leg, payloadSize);
}

void MPTCPOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6MPOption *opt = rawOptCast<SOCKS6MPOption>(optBase, false);
	SOCKS6StackLeg leg = (SOCKS6StackLeg)opt->stackOptionHead.leg;
	bool avail = opt->availability;
	
	optionSet->stack()->mptcp()->set(leg, avail);
}

void BacklogOption::incrementalParse(SOCKS6StackOption *optBase, OptionSet *optionSet)
{
	SOCKS6BacklogOption *opt = rawOptCast<SOCKS6BacklogOption>(optBase, false);
	SOCKS6StackLeg leg = (SOCKS6StackLeg)opt->stackOptionHead.leg;
	uint8_t backlog = ntohs(opt->backlog);
	
	optionSet->stack()->backlog()->set(leg, backlog);
}

BacklogOption::BacklogOption(SOCKS6StackLeg leg, uint16_t backlog)
	: StackOptionBase(leg, backlog)
{
	if (backlog < SOCKS6_BACKLOG_MIN)
		throw invalid_argument("Bad backlog size");
}

}
