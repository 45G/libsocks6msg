#include <boost/foreach.hpp>
#include "socks6msg_optionset.hh"

using namespace std;
using namespace boost;

namespace S6M
{

OptionSet::OptionSet()
	: tfo(false), mptcp(false) {}

OptionSet::~OptionSet() {}

void OptionSet::parse(ByteBuffer *bb)
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	for (int i = 0; i < optsHead->optionCount; i++)
	{
		SOCKS6Option *opt = bb->get<SOCKS6Option>();
		
		/* bad option length wrecks everything */
		if (opt->len < 2)
			throw Exception(S6M_ERR_INVALID);
	
		bb->get<uint8_t>(opt->len - sizeof(SOCKS6Option));
		
		try
		{
			opts.push_back(shared_ptr<Option>(Option::parse(opt)));
		}
		catch (Exception ex)
		{
			/* silently ignote bad options */
			if (ex.getError() == S6M_ERR_INVALID)
				continue;
			throw ex;
		}
	}
}

void OptionSet::pack(ByteBuffer *bb)
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	if (opts.size() > 255)
		throw Exception(S6M_ERR_INVALID);
	
	optsHead->optionCount = opts.size();
	
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		opt->pack(bb);
	}
}

}
