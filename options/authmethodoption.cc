#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include "authmethodoption.hh"
#include "optionset.hh"
#include "padded.hh"

using namespace std;

namespace S6M
{

size_t AuthMethodAdvertOption::packedSize() const
{
	return unpaddedSize() + paddingOf(unpaddedSize());
}

void AuthMethodAdvertOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthMethodAdvertOption *opt = reinterpret_cast<SOCKS6AuthMethodAdvertOption *>(buf);
	
	opt->initialDataLen = htons(initialDataLen);

	int i = 0;
	BOOST_FOREACH(SOCKS6Method method, methods)
	{
		opt->methods[i] = method;
		i++;
	}
	
	for (int j = 0; j < (int)paddingOf(unpaddedSize()); j++)
		opt->methods[i + j] = 0;
}

void AuthMethodAdvertOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6AuthMethodAdvertOption *opt = rawOptCast<SOCKS6AuthMethodAdvertOption>(optBase);

	uint16_t initDataLen = ntoh(opt->initialDataLen);
	
	int methodCount = ntoh(opt->optionHead.len) - sizeof(SOCKS6AuthMethodAdvertOption);
	
	set<SOCKS6Method> methods;
	for (int i = 0; i < methodCount; i++)
		methods.insert((SOCKS6Method)opt->methods[i]);
	
	optionSet->authMethods.advertise(methods, initDataLen);
}

AuthMethodAdvertOption::AuthMethodAdvertOption(uint16_t initialDataLen, std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD_ADVERT), initialDataLen(initialDataLen), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw invalid_argument("Bad method");
	methods.erase(SOCKS6_METHOD_NOAUTH);
	if (methods.empty())
		throw invalid_argument("No methods");
}

void AuthMethodSelectOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthMethodSelectOption *opt = reinterpret_cast<SOCKS6AuthMethodSelectOption *>(buf);
	
	opt->method = method;
	memset(opt->padding, 0, sizeof(opt->padding));
}

size_t AuthMethodSelectOption::packedSize() const
{
	return sizeof(SOCKS6AuthMethodSelectOption);
}

void AuthMethodSelectOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6AuthMethodSelectOption *opt = rawOptCast<SOCKS6AuthMethodSelectOption>(optBase, false);
	
	optionSet->authMethods.select((SOCKS6Method)opt->method);
}

AuthMethodSelectOption::AuthMethodSelectOption(SOCKS6Method method)
	: Option(SOCKS6_OPTION_AUTH_METHOD_ADVERT), method(method)
{
	if (method == SOCKS6_METHOD_NOAUTH)
		throw logic_error("Bad method");
}

}
