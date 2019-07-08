#include "resolutionoption.hh"
#include "optionset.hh"

using namespace std;

void S6M::ResolutionRequestOption::simpleParse(S6M::OptionSet *optionSet)
{
	optionSet->resolution.request();
}

size_t S6M::DomainResolutionOption::packedSize() const
{
	size_t ret = sizeof(SOCKS6Option);

	BOOST_FOREACH(Padded<String> addr, addressFields)
	{
		ret += addr.packedSize();
	}
	return ret;
}

S6M::DomainResolutionOption::DomainResolutionOption(const std::list<string> &addresses)
	: Option(SOCKS6_OPTION_RESOLVE_DOMAIN), addresses(addresses)
{
	BOOST_FOREACH(string addr, addresses)
	{
		addressFields.push_back(Padded<String>(addr));
	}
}

void S6M::DomainResolutionOption::incrementalParse(SOCKS6Option *optBase, S6M::OptionSet *optionSet)
{
	size_t length = ntohs(optBase->len);
	size_t payloadLength = length - sizeof(SOCKS6Option);

	list<string> addresses;
	ByteBuffer bb(optBase->data, payloadLength);
	while (bb.getUsed() > 0)
		addresses.push_back(*Padded<String>(&bb).getStr());

	optionSet->resolution.setDomains(addresses);
}

void S6M::IPv4ResolutionOption::resolutionParse(const std::list<in_addr> &addresses, OptionSet *optionSet)
{
	optionSet->resolution.setIPv4(addresses);
}

void S6M::IPv6ResolutionOption::resolutionParse(const std::list<in6_addr> &addresses, OptionSet *optionSet)
{
	optionSet->resolution.setIPv6(addresses);
}
