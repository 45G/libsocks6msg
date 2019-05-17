#include <arpa/inet.h>
#include <list>
#include <boost/foreach.hpp>
#include "option.hh"
#include "stackoption.hh"
#include "idempotenceoption.hh"
#include "authmethodoption.hh"
#include "authdataoption.hh"
#include "optionset.hh"
#include "sanity.hh"

using namespace std;
using namespace boost;

namespace S6M
{

void Option::fill(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = htons(getKind());
	opt->len  = htons(packedSize());
}

void Option::incrementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6Option *opt = rawOptCast<SOCKS6Option>(buf);
	uint16_t kind = ntohs(opt->kind);
	
	switch (kind) {
	case SOCKS6_OPTION_STACK:
		StackOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_METHOD:
		AuthMethodOption::incrementalParse(opt, optionLen, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_DATA:
		AuthDataOption::incrementalParse(opt, optionLen, optionSet);
		break;
		
	case SOCKS6_OPTION_SESSION:
		SessionOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_OPTION_IDEMPOTENCE:
		IdempotenceOption::incrementalParse(opt, optionSet);
		break;
		
	default:
		throw invalid_argument("Unknown kind");
	}
}

Option::~Option() {}

}
