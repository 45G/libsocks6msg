#ifndef RESOLUTIONOPTION_HH
#define RESOLUTIONOPTION_HH

#include <list>
#include <unordered_set>
#include <boost/foreach.hpp>
#include "option.hh"
#include "string.hh"
#include "padded.hh"

namespace S6M
{

class ResolutionRequestOption: SimpleOptionBase<ResolutionRequestOption, SOCKS6_OPTION_RESOLVE_REQ>
{
	static void simpleParse(OptionSet *optionSet);
};

template <SOCKS6OptionKind K, typename A>
class ForwardResolutionOptionBase: public Option
{
	struct RawOption
	{
		SOCKS6Option optionHead;
		A addresses[0];
	};

	std::unordered_set<A> addresses;

public:
	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6Option) + addresses.size() * sizeof(A);
	}

	ForwardResolutionOptionBase(const std::unordered_set<A> &addresses)
		: Option(K), addresses(addresses) {}

	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
	{
		RawOption *opt = rawOptCast<RawOption>(optBase, true);
		size_t length = ntohs(optBase->len);
		size_t payloadLength = length - sizeof(SOCKS6Option);

		if (payloadLength % sizeof(A) != 0)
			throw std::length_error("Bad payload length");

		std::unordered_set<A> addresses;
		int entries = payloadLength / sizeof(A);
		for (int i = 0; i < entries; i++)
			addresses.insert(opt->addresses[i]);

		//TODO
	}

	const std::unordered_set<A> *getAddresses() const
	{
		return &addresses;
	}
};

typedef ForwardResolutionOptionBase<SOCKS6_OPTION_RESOLVE_IPv4, in_addr>  IPv4ResolutionOption;

typedef ForwardResolutionOptionBase<SOCKS6_OPTION_RESOLVE_IPv6, in6_addr> IPv6ResolutionOption;

class DomainResolutionOption: public Option
{
	std::unordered_set<std::string> addresses;
	std::list<Padded<String>> addressFields;

public:
	virtual size_t packedSize() const;

	DomainResolutionOption(const std::unordered_set<std::string> &addresses);

	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);

	const std::unordered_set<std::string> *getAddresses() const
	{
		return &addresses;
	}
};

}

#endif // RESOLUTIONOPTION_HH
