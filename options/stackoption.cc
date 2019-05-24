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
			MPOption::incrementalParse(opt, optionSet);
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

void TOSOption::stackParse(RawOption *opt, OptionSet *optionSet)
{
	optionSet->stack.tos.set((SOCKS6StackLeg)opt->stackOptionHead.leg, opt->value);
}

void TFOOption::stackParse(RawOption *opt, OptionSet *optionSet)
{
	optionSet->stack.tfo.set((SOCKS6StackLeg)opt->stackOptionHead.leg, ntohs(opt->value));
}

void MPOption::stackParse(RawOption *opt, OptionSet *optionSet)
{
	optionSet->stack.mp.set((SOCKS6StackLeg)opt->stackOptionHead.leg, enumCast<SOCKS6MPAvailability>(opt->value));
}

void BacklogOption::stackParse(RawOption *opt, OptionSet *optionSet)
{
	optionSet->stack.backlog.set((SOCKS6StackLeg)opt->stackOptionHead.leg, ntohs(opt->value));
}

BacklogOption::BacklogOption(SOCKS6StackLeg leg, uint16_t backlog)
	: StackOptionBase(leg, backlog)
{
	if (backlog < SOCKS6_BACKLOG_MIN)
		throw invalid_argument("Bad backlog size");
}

}
