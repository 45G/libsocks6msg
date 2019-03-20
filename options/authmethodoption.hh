#ifndef SOCKS6MSG_AUTHMETHODOPTION_HH
#define SOCKS6MSG_AUTHMETHODOPTION_HH

#include "option.hh"

namespace S6M
{

class AuthMethodOption: public Option
{
	uint16_t initialDataLen;
	std::set<SOCKS6Method> methods;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6Option *optBase, size_t optionLen, OptionSet *optionSet);
	
	AuthMethodOption(uint16_t initialDataLen, std::set<SOCKS6Method> methods);

	uint16_t getInitialDataLen() const
	{
		return initialDataLen;
	}

	const std::set<SOCKS6Method> *getMethods() const
	{
		return &methods;
	}
};

}

#endif // SOCKS6MSG_AUTHMETHODOPTION_HH
