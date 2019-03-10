#include <string>
#include "authdataoption.hh"
#include "optionset.hh"

using namespace std;

namespace S6M
{

void AuthDataOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	opt->method = method;
}

void AuthDataOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = rawOptCast<SOCKS6AuthDataOption>(buf, optionLen);
	
	switch (opt->method)
	{
	/* invalid, but handled by default */
//	case SOCKS6_METHOD_NOAUTH:
//	case SOCKS6_METHOD_UNACCEPTABLE:
//		throw InvalidFieldException();
		
	case SOCKS6_METHOD_USRPASSWD:
		UsernamePasswdOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	default:
		throw invalid_argument("Unsupported method");
	}	
}

size_t UsernamePasswdOption::packedSize() const
{
	return sizeof(SOCKS6AuthDataOption) + req.packedSize();
}

void UsernamePasswdOption::fill(uint8_t *buf) const
{
	AuthDataOption::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	ByteBuffer bb(opt->methodData, req.packedSize());
	
	req.pack(&bb);
}

void UsernamePasswdOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	size_t expectedDataSize = optionLen - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		UserPasswordRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw invalid_argument("Spurious bytes at the end of the option");
		
		optionSet->setUsernamePassword(req.getUsername(), req.getPassword());
	}
	catch (EndOfBufferException)
	{
		throw invalid_argument("Truncated payload");
	}
	catch (BadVersionException)
	{
		throw invalid_argument("Unsupported version");
	}
}

UsernamePasswdOption::UsernamePasswdOption(std::shared_ptr<string> username, std::shared_ptr<string> passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), req(username, passwd) {}

}
