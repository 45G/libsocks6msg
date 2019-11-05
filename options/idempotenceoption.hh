#ifndef SOCKS6MSG_IDEMPOTENCEOPTION_HH
#define SOCKS6MSG_IDEMPOTENCEOPTION_HH

#include "option.hh"
#include "restrictedint.hh"

namespace S6M
{

typedef BoundedInt<uint32_t, SOCKS6_TOKEN_WINDOW_MIN, SOCKS6_TOKEN_WINDOW_MAX> WindowSize;

class IdempotenceRequestOption: public Option
{
	WindowSize winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	IdempotenceRequestOption(uint32_t winSize)
		: Option(SOCKS6_OPTION_IDEMPOTENCE_REQ), winSize(winSize) {}

	uint32_t getWinSize() const
	{
		return winSize;
	}
};

class IdempotenceWindowOption: public Option
{
	uint32_t winBase;
	WindowSize winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	IdempotenceWindowOption(std::pair<uint32_t, uint32_t> window)
		: Option(SOCKS6_OPTION_IDEMPOTENCE_WND), winBase(window.first), winSize(window.second) {}
	
	std::pair<uint32_t, uint32_t> getWindow() const
	{
		return { winBase, winSize };
	}
};

class IdempotenceExpenditureOption: public Option
{
	uint32_t token;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	IdempotenceExpenditureOption(uint32_t token)
		: Option(SOCKS6_OPTION_IDEMPOTENCE_EXPEND), token(token) {}

	uint32_t getToken() const
	{
		return token;
	}
};

class IdempotenceAcceptedOption: public SimpleOptionBase<IdempotenceAcceptedOption, SOCKS6_OPTION_IDEMPOTENCE_ACCEPT>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

class IdempotenceRejectedOption: public SimpleOptionBase<IdempotenceRejectedOption, SOCKS6_OPTION_IDEMPOTENCE_REJECT>
{
public:
	static void simpleParse(OptionSet *optionSet);
};

}

#endif // SOCKS6MSG_IDEMPOTENCEOPTION_HH
