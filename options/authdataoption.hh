#ifndef SOCKS6MSG_AUTHDATAOPTION_HH
#define SOCKS6MSG_AUTHDATAOPTION_HH

#include "option.hh"

namespace S6M
{

class AuthDataOption: public Option
{
	SOCKS6Method method;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SOCKS6Method getMethod() const
	{
		return method;
	}
	
	static void incrementalParse(SOCKS6Option *optBase, size_t optionLen, OptionSet *optionSet);
	
	AuthDataOption(SOCKS6Method method)
		: Option(SOCKS6_OPTION_AUTH_DATA), method(method) {}
};

class UsernamePasswdOption: public AuthDataOption
{
	UserPasswordRequest req;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6AuthDataOption *optBase, size_t optionLen, OptionSet *optionSet);
	
	UsernamePasswdOption(const std::string &username, const std::string &passwd);

	const std::string *getUsername() const
	{
		return req.getUsername();
	}

	const std::string *getPassword() const
	{
		return req.getPassword();
	}
};

}

#endif // SOCKS6MSG_AUTHDATAOPTION_HH
