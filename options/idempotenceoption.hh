#ifndef SOCKS6MSG_IDEMPOTENCEOPTION_HH
#define SOCKS6MSG_IDEMPOTENCEOPTION_HH

#include "option.hh"

namespace S6M
{

class IdempotenceOption: public Option
{
	SOCKS6IDempotenceType type;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	IdempotenceOption(SOCKS6IDempotenceType type)
		: Option(SOCKS6_OPTION_IDEMPOTENCE), type(type) {}

	SOCKS6IDempotenceType getType() const
	{
		return type;
	}
};

class TokenWindowRequestOption: public IdempotenceOption
{
	uint32_t winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	TokenWindowRequestOption(uint32_t winSize);

	uint32_t getWinSize() const
	{
		return winSize;
	}
};

class TokenWindowAdvertOption: public IdempotenceOption
{
	uint32_t winBase;
	uint32_t winSize;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
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

class TokenExpenditureRequestOption: public IdempotenceOption
{
	uint32_t token;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	TokenExpenditureRequestOption(uint32_t token)
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND), token(token) {}

	uint32_t getToken() const
	{
		return token;
	}
};

class TokenExpenditureReplyOption: public IdempotenceOption
{
	SOCKS6TokenExpenditureCode code;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incementalParse(void *buf, OptionSet *optionSet);
	
	TokenExpenditureReplyOption(SOCKS6TokenExpenditureCode code)
		: IdempotenceOption(SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY), code(code) {}

	SOCKS6TokenExpenditureCode getCode() const
	{
		return code;
	}
};

}

#endif // SOCKS6MSG_IDEMPOTENCEOPTION_HH
