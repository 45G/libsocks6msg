#ifndef SOCKS6MSG_OPTION_HH
#define SOCKS6MSG_OPTION_HH

#include <arpa/inet.h>
#include <set>
#include <vector>
#include <string>
#include <stdexcept>
#include <boost/intrusive/list.hpp>
#include "socks6.h"
#include "bytebuffer.hh"
#include "usrpasswd.hh"

namespace S6M
{

class OptionSet;

class Option: public boost::intrusive::list_base_hook<boost::intrusive::link_mode<boost::intrusive::auto_unlink>>
{
	SOCKS6OptionKind kind;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
	template <typename T>
	static T *rawOptCast(void *buf, bool allowPayload = true)
	{
		size_t len = ntohs(((SOCKS6Option *)buf)->len);
		
		if (len < sizeof(T))
			throw std::invalid_argument("Truncated option");
		if (!allowPayload && len != sizeof(T))
			throw std::invalid_argument("Spurious bytes at the end of the option");
		
		return (T *)buf;
	}
	
public:
	SOCKS6OptionKind getKind() const
	{
		return kind;
	}
	
	virtual size_t packedSize() const = 0;
	
	void pack(ByteBuffer *bb) const
	{
		uint8_t *buf = bb->get<uint8_t>(packedSize());
		
		fill(buf);
	}
	
	static void incrementalParse(void *buf, OptionSet *optionSet);
	
	Option(SOCKS6OptionKind kind)
		: kind(kind) {}
	
	virtual ~Option();
};

template <typename T, SOCKS6OptionKind K>
class SimpleOptionBase: public Option
{
public:
	SimpleOptionBase()
		: Option(K) {}

	virtual size_t packedSize() const
	{
		return sizeof(SOCKS6Option);
	}

	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
	{
		rawOptCast<SOCKS6Option>(optBase, false);
		T::simpleParse(optionSet);
	}

	static void simpleParse(OptionSet *optionSet);
};

}

#endif // SOCKS6MSG_OPTION_HH
