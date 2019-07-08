#include "resolutionoption.hh"

using namespace std;

void S6M::ResolutionRequestOption::simpleParse(S6M::OptionSet *optionSet)
{
	//TODO
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

S6M::DomainResolutionOption::DomainResolutionOption(const std::unordered_set<string> &addresses)
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

	unordered_set<string> addresses;
	ByteBuffer bb(optBase->data, payloadLength);
	while (bb.getUsed() > 0)
		addresses.insert(*Padded<String>(&bb).getStr());

	//TODO
}
