#ifndef SOCKS6MSG_AUTHDATAOPTION_HH
#define SOCKS6MSG_AUTHDATAOPTION_HH

#include "option.hh"
#include "padded.hh"

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
	
	static void incrementalParse(SOCKS6Option *baseOpt, OptionSet *optionSet);
	
	AuthDataOption(SOCKS6Method method)
		: Option(SOCKS6_OPTION_AUTH_DATA), method(method) {}
};

class UsernamePasswdReqOption: public AuthDataOption
{
	typedef Padded<UserPasswordRequest, sizeof(SOCKS6AuthDataOption)> PaddedRequest;
	
	PaddedRequest req;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6AuthDataOption *baseOpt, OptionSet *optionSet);
	
	UsernamePasswdReqOption(const std::pair<std::string_view, std::string_view> &creds);
	
	std::pair<std::string_view, std::string_view> getCredentials() const
	{
		return req.getCredentials();
	}
};

class UsernamePasswdReplyOption: public AuthDataOption
{
	bool success;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	virtual size_t packedSize() const;
	
	static void incrementalParse(SOCKS6AuthDataOption *baseOpt, OptionSet *optionSet);
	
	UsernamePasswdReplyOption(bool success)
		: AuthDataOption(SOCKS6_METHOD_USRPASSWD), success(success) {}

	bool isSuccessful() const
	{
		return success;
	}
};

}

#endif // SOCKS6MSG_AUTHDATAOPTION_HH
