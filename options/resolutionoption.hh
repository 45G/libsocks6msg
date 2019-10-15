#ifndef RESOLUTIONOPTION_HH
#define RESOLUTIONOPTION_HH

#include <list>
#include <unordered_set>
#include "option.hh"
#include "string.hh"
#include "padded.hh"

namespace S6M
{

class ResolutionRequestOption: public SimpleOptionBase<ResolutionRequestOption, SOCKS6_OPTION_RESOLVE_REQ>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

template <typename T, SOCKS6OptionKind K, typename A>
class ForwardResolutionOptionBase: public Option
{
	struct RawOption
	{
		SOCKS6Option optionHead;
		A addresses[0];
	};

	std::list<A> addresses;

public:
	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6Option) + addresses.size() * sizeof(A);
	}

	ForwardResolutionOptionBase(const std::list<A> &addresses)
		: Option(K), addresses(addresses) {}

	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
	{
		RawOption *opt = rawOptCast<RawOption>(optBase, true);
		size_t length = ntohs(optBase->len);
		size_t payloadLength = length - sizeof(SOCKS6Option);

		if (payloadLength % sizeof(A) != 0)
			throw std::length_error("Bad payload length");

		std::list<A> addresses;
		int entries = payloadLength / sizeof(A);
		for (int i = 0; i < entries; i++)
			addresses.push_back(opt->addresses[i]);

		T::resolutionParse(addresses, optionSet);
	}

	const std::list<A> *getAddresses() const
	{
		return &addresses;
	}

	static void resolutionParse(const std::list<A> &addresses, OptionSet *optionSet);
};

class IPv4ResolutionOption : public ForwardResolutionOptionBase<IPv4ResolutionOption, SOCKS6_OPTION_RESOLVE_IPv4, in_addr>
{
public:
	using ForwardResolutionOptionBase::ForwardResolutionOptionBase;

	static void resolutionParse(const std::list<in_addr> &addresses, OptionSet *optionSet);
};

class IPv6ResolutionOption: public ForwardResolutionOptionBase<IPv6ResolutionOption, SOCKS6_OPTION_RESOLVE_IPv6, in6_addr>
{
public:
	using ForwardResolutionOptionBase::ForwardResolutionOptionBase;

	static void resolutionParse(const std::list<in6_addr> &addresses, OptionSet *optionSet);
};

class DomainResolutionOption: public Option
{
	std::list<std::string> addresses;
	std::list<Padded<String>> addressFields;

public:
	virtual size_t packedSize() const;

	DomainResolutionOption(const std::list<std::string> &addresses);

	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);

	const std::list<std::string> *getAddresses() const
	{
		return &addresses;
	}
};

}

#endif // RESOLUTIONOPTION_HH
