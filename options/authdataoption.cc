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

void AuthDataOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	if (opt->optionHead.len < sizeof(SOCKS6AuthDataOption))
		throw InvalidFieldException();
	
	switch (opt->method)
	{
	/* invalid, but handled by default */
//	case SOCKS6_METHOD_NOAUTH:
//	case SOCKS6_METHOD_UNACCEPTABLE:
//		throw InvalidFieldException();
		
	case SOCKS6_METHOD_USRPASSWD:
		UsernamePasswdOption::incementalParse(buf, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
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
	
	ByteBuffer bb(opt->methodData, opt->optionHead.len - sizeof(SOCKS6AuthDataOption));
	
	req.pack(&bb);
}

void UsernamePasswdOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)buf;
	
	size_t expectedDataSize = opt->optionHead.len - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		UserPasswordRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw InvalidFieldException();
		
		optionSet->setUsernamePassword(req.getUsername(), req.getPassword());
	}
	catch (EndOfBufferException)
	{
		throw InvalidFieldException();
	}
	catch (BadVersionException)
	{
		throw InvalidFieldException();
	}
}

UsernamePasswdOption::UsernamePasswdOption(std::shared_ptr<string> username, std::shared_ptr<string> passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), req(username, passwd) {}

}
