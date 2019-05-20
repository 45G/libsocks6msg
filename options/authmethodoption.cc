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

void AuthMethodAdvertOption::incrementalParse(SOCKS6Option *optBase, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6AuthMethodAdvertOption *opt = rawOptCast<SOCKS6AuthMethodAdvertOption>(optBase);

	uint16_t initDataLen = ntoh(opt->initialDataLen);
	
	int methodCount = optionLen - sizeof(SOCKS6AuthMethodAdvertOption);
	
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

}
