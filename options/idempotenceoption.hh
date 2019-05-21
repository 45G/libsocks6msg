#ifndef SOCKS6MSG_IDEMPOTENCEOPTION_HH
#define SOCKS6MSG_IDEMPOTENCEOPTION_HH

#include "option.hh"

namespace S6M
{

class TokenWindowRequestOption: public Option
{
	uint32_t winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	TokenWindowRequestOption(uint32_t winSize);

	uint32_t getWinSize() const
	{
		return winSize;
	}
};

class TokenWindowAdvertOption: public Option
{
	uint32_t winBase;
	uint32_t winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize);

	uint32_t getWinBase() const
	{
		return winBase;
	}

	uint32_t getWinSize() const
	{
		return winSize;
	}
};

class TokenExpenditureRequestOption: public Option
{
	uint32_t token;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	TokenExpenditureRequestOption(uint32_t token)
		: Option(SOCKS6_OPTION_IDEMPOTENCE_EXPEND), token(token) {}

	uint32_t getToken() const
	{
		return token;
	}
};

class TokenExpenditureReplyOption: public Option
{
	SOCKS6TokenExpenditureCode code;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code)
		: Option(SOCKS6_OPTION_IDEMPOTENCE_EXPEND_REPLY), code(code) {}

	SOCKS6TokenExpenditureCode getCode() const
	{
		return code;
	}
};

}

#endif // SOCKS6MSG_IDEMPOTENCEOPTION_HH
