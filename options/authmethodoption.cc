#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include "authmethodoption.hh"
#include "optionset.hh"

using namespace std;

namespace S6M
{

size_t AuthMethodOption::packedSize() const
{
	return sizeof(SOCKS6Option) + methods.size() * sizeof(uint8_t);
}

void AuthMethodOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthMethodOption *opt = reinterpret_cast<SOCKS6AuthMethodOption *>(buf);
	
	opt->initialDataLen = htons(initialDataLen);

	int i = 0;
	BOOST_FOREACH(SOCKS6Method method, methods)
	{
		opt->methods[i] = method;
		i++;
	}
}

void AuthMethodOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6AuthMethodOption *opt = rawOptCast<SOCKS6AuthMethodOption>(buf);

	optionSet->setInitialDataLen(ntohs(opt->initialDataLen));
	
	int methodCount = optionLen - sizeof(SOCKS6AuthMethodOption);
	
	for (int i = 0; i < methodCount; i++)
		optionSet->advertiseMethod((SOCKS6Method)opt->methods[i]);
}

AuthMethodOption::AuthMethodOption(uint16_t initialDataLen, std::set<SOCKS6Method> methods)
	: Option(SOCKS6_OPTION_AUTH_METHOD), initialDataLen(initialDataLen), methods(methods)
{
	if (methods.find(SOCKS6_METHOD_UNACCEPTABLE) != methods.end())
		throw invalid_argument("Bad method");
	methods.erase(SOCKS6_METHOD_NOAUTH);
	if (methods.empty())
		throw invalid_argument("No methods");
}

}
