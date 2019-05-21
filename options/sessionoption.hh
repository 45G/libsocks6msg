#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

#include <vector>
#include "option.hh"

namespace S6M
{

class SessionRequestOption: public SimpleOptionBase<SessionRequestOption>
{
public:
	SessionRequestOption()
		: SimpleOptionBase(SOCKS6_OPTION_SESSION_REQUEST) {}
	
	static void simpleParse(SOCKS6Option *, OptionSet *optionSet);
};

class SessionIDOption: public Option
{
	std::vector<uint8_t> ticket;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionIDOption(const std::vector<uint8_t> &ticket);
	
	const std::vector<uint8_t> *getTicket() const
	{
		return &ticket;
	}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *buf, OptionSet *optionSet);
};

class SessionTeardownOption: public SimpleOptionBase<SessionTeardownOption>
{
public:
	SessionTeardownOption()
		: SimpleOptionBase(SOCKS6_OPTION_SESSION_TEARDOWN) {}
	
	static void simpleParse(SOCKS6Option *, OptionSet *optionSet);
};

class SessionOKOption: public SimpleOptionBase<SessionOKOption>
{
public:
	SessionOKOption()
		: SimpleOptionBase(SOCKS6_OPTION_SESSION_OK) {}
	
	static void simpleParse(SOCKS6Option *, OptionSet *optionSet);
};

class SessionInvalidOption: public SimpleOptionBase<SessionInvalidOption>
{
public:
	SessionInvalidOption()
		: SimpleOptionBase(SOCKS6_OPTION_SESSION_INVALID) {}
	
	static void simpleParse(SOCKS6Option *, OptionSet *optionSet);
};

class SessionUntrustedOption: public SimpleOptionBase<SessionUntrustedOption>
{
public:
	SessionUntrustedOption()
		: SimpleOptionBase(SOCKS6_OPTION_SESSION_UNTRUSTED) {}
	
	static void simpleParse(SOCKS6Option *, OptionSet *optionSet);
};

}
#endif // SOCKS6MSG_SESSIONOPTION_HH
