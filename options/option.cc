#include <arpa/inet.h>
#include <list>
#include <boost/foreach.hpp>
#include "option.hh"
#include "stackoption.hh"
#include "idempotenceoption.hh"
#include "authmethodoption.hh"
#include "authdataoption.hh"
#include "optionset.hh"
#include "../util/sanity.hh"

using namespace std;
using namespace boost;

namespace S6M
{

void Option::fill(uint8_t *buf) const
{
	SOCKS6Option *opt = reinterpret_cast<SOCKS6Option *>(buf);
	
	opt->kind = getKind();
	opt->len  = htons(packedSize());
}

void Option::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6Option *opt = (SOCKS6Option *)buf;
	
	switch (opt->kind) {
	case SOCKS6_OPTION_STACK:
		StackOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_METHOD:
		AuthMethodOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_OPTION_AUTH_DATA:
		AuthDataOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_OPTION_IDEMPOTENCE:
		IdempotenceOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}
}

Option::~Option() {}

}
