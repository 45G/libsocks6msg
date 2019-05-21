#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

#include <vector>
#include "option.hh"

namespace S6M
{

class SessionRequestOption: public Option
{
public:
	SessionRequestOption()
		: Option(SOCKS6_OPTION_SESSION_REQUEST) {}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
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

class SessionTeardownOption: public Option
{
public:
	SessionTeardownOption()
		: Option(SOCKS6_OPTION_SESSION_TEARDOWN) {}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
};

class SessionOKOption: public Option
{
public:
	SessionOKOption()
		: Option(SOCKS6_OPTION_SESSION_OK) {}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
};

class SessionInvalidOption: public Option
{
public:
	SessionInvalidOption()
		: Option(SOCKS6_OPTION_SESSION_INVALID) {}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
};

class SessionUntrustedOption: public Option
{
public:
	SessionUntrustedOption()
		: Option(SOCKS6_OPTION_SESSION_UNTRUSTED) {}
	
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
};

}
#endif // SOCKS6MSG_SESSIONOPTION_HH
