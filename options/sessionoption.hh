#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

#include <vector>
#include "option.hh"

namespace S6M
{

class SessionRequestOption: public SimpleOptionBase<SessionRequestOption, SOCKS6_OPTION_SESSION_REQUEST>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class SessionIDOption: public Option
{
	std::vector<uint8_t> id;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionIDOption(const std::vector<uint8_t> &id);
	
	const std::vector<uint8_t> *getID() const
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
