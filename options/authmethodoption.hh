#ifndef SOCKS6MSG_AUTHMETHODOPTION_HH
#define SOCKS6MSG_AUTHMETHODOPTION_HH

#include "option.hh"

namespace S6M
{

class AuthMethodAdvertOption: public Option
{
	uint16_t initialDataLen;
	std::set<SOCKS6Method> methods;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
	size_t unpaddedSize() const
	{
		return sizeof(SOCKS6Option) + methods.size() * sizeof(uint8_t);
	}
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, size_t optionLen, OptionSet *optionSet);
	
	AuthMethodAdvertOption(uint16_t initialDataLen, std::set<SOCKS6Method> methods);

	uint16_t getInitialDataLen() const
	{
		return initialDataLen;
	}

	const std::set<SOCKS6Method> *getMethods() const
	{
		return &methods;
	}
};

class AuthMethodSelectOption: public Option
{
	SOCKS6Method method;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet);
	
	AuthMethodSelectOption(SOCKS6Method method);

	SOCKS6Method getMethod() const
	{
		return method;
	}
};

}

#endif // SOCKS6MSG_AUTHMETHODOPTION_HH
