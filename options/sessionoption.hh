#ifndef SOCKS6MSG_SESSIONOPTION_HH
#define SOCKS6MSG_SESSIONOPTION_HH

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
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionRequestOption: public SessionOption
{
public:
	SessionRequestOption()
		: SessionOption(SOCKS6_SESSION_REQUEST) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionTeardownOption: public SessionOption
{
public:
	SessionTeardownOption()
		: SessionOption(SOCKS6_SESSION_TEARDOWN) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionTicketOption: public SessionOption
{
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionTicketOption()
		: SessionOption(SOCKS6_SESSION_TICKET) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionOKOption: public SessionOption
{
public:
	SessionOKOption()
		: SessionOption(SOCKS6_SESSION_OK) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionInexistentOption: public SessionOption
{
public:
	SessionInexistentOption()
		: SessionOption(SOCKS6_SESSION_INEXISTENT) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

class SessionTicketUpdateOption: public SessionOption
{
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SessionTicketUpdateOption()
		: SessionOption(SOCKS6_SESSION_TICKET_UPDATE) {}
	
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
};

}
#endif // SOCKS6MSG_SESSIONOPTION_HH
