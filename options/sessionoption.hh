#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

#include <vector>
#include <boost/container/small_vector.hpp>
#include "option.hh"

namespace S6M
{

static constexpr int SESSION_ID_PREALLOC = 32;

using
SessionID = boost::container::small_vector<uint8_t, SESSION_ID_PREALLOC>;

class SessionRequestOption: public SimpleOptionBase<SessionRequestOption, SOCKS6_OPTION_SESSION_REQUEST>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class SessionIDOption: public Option
{
	SessionID id;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionIDOption(const SessionID &id);
	
	const SessionID *getID() const
	{
		return &id;
	}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *buf, OptionSet *optionSet);
};

class SessionTeardownOption: public SimpleOptionBase<SessionTeardownOption, SOCKS6_OPTION_SESSION_TEARDOWN>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class SessionOKOption: public SimpleOptionBase<SessionOKOption, SOCKS6_OPTION_SESSION_OK>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class SessionInvalidOption: public SimpleOptionBase<SessionInvalidOption, SOCKS6_OPTION_SESSION_INVALID>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class SessionUntrustedOption: public SimpleOptionBase<SessionUntrustedOption, SOCKS6_OPTION_SESSION_UNTRUSTED>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

}
#endif // SOCKS6MSG_SESSIONOPTION_HH
