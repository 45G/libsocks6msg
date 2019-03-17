#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

#include <vector>
#include "option.hh"

namespace S6M
{

class SessionOption: public Option
{
	SOCKS6SessionType type;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionOption(SOCKS6SessionType type)
		: Option(SOCKS6_OPTION_SESSION), type(type) {}
	
	SOCKS6SessionType getType() const
	{
		return type;
	}
	
	static void incementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
};

class SessionRequestOption: public SessionOption
{
public:
	SessionRequestOption()
		: SessionOption(SOCKS6_SESSION_REQUEST) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet);
};

class SessionIDOption: public SessionOption
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
	
	static void incementalParse(SOCKS6SessionOption *buf, OptionSet *optionSet);
};

class SessionTeardownOption: public SessionOption
{
public:
	SessionTeardownOption()
		: SessionOption(SOCKS6_SESSION_TEARDOWN) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet);
};

class SessionOKOption: public SessionOption
{
public:
	SessionOKOption()
		: SessionOption(SOCKS6_SESSION_OK) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet);
};

class SessionInvalidOption: public SessionOption
{
public:
	SessionInvalidOption()
		: SessionOption(SOCKS6_SESSION_INVALID) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet);
};

class SessionUntrustedOption: public SessionOption
{
public:
	SessionUntrustedOption()
		: SessionOption(SOCKS6_SESSION_UNTRUSTED) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet);
};

}
#endif // SOCKS6MSG_SESSIONOPTION_HH
