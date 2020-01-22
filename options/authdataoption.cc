#include <string>
#include "authdataoption.hh"
#include "optionset.hh"
#include "exceptions.hh"

using namespace std;

namespace S6M
{

void AuthDataOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	opt->method = method;
}

void AuthDataOption::incrementalParse(SOCKS6Option *baseOpt, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = rawOptCast<SOCKS6AuthDataOption>(baseOpt);
	
	switch (opt->method)
	{
	case SOCKS6_METHOD_NOAUTH:
	case SOCKS6_METHOD_UNACCEPTABLE:
		throw invalid_argument("Bad method");
		
	case SOCKS6_METHOD_USRPASSWD:
		if (optionSet->getMode() == OptionSet::M_REQ)
			UsernamePasswdReqOption::incrementalParse(opt, optionSet);
		else
			UsernamePasswdReplyOption::incrementalParse(opt, optionSet);
		break;
		
	default:
		throw invalid_argument("Unsupported method");
	}	
}

size_t UsernamePasswdReqOption::packedSize() const
{
	return sizeof(SOCKS6AuthDataOption) + req.packedSize();
}

void UsernamePasswdReqOption::fill(uint8_t *buf) const
{
	AuthDataOption::fill(buf);
	
	SOCKS6AuthDataOption *opt = reinterpret_cast<SOCKS6AuthDataOption *>(buf);
	
	ByteBuffer bb(opt->methodData, req.packedSize());
	
	req.pack(&bb);
}

void UsernamePasswdReqOption::incrementalParse(SOCKS6AuthDataOption *baseOpt, OptionSet *optionSet)
{
	SOCKS6AuthDataOption *opt = (SOCKS6AuthDataOption *)baseOpt;
	
	size_t expectedDataSize = ntoh(opt->optionHead.len) - sizeof(SOCKS6AuthDataOption);
	
	try
	{
		ByteBuffer bb(opt->methodData, expectedDataSize);
		PaddedRequest req(&bb);
		
		if (bb.getUsed() != expectedDataSize)
			throw invalid_argument("Spurious bytes at the end of the option");
		
		optionSet->userPassword.setCredentials(req.username->getStr(), req.password->getStr());
	}
	catch (length_error &)
	{
		throw invalid_argument("Truncated payload");
	}
	catch (BadVersionException &)
	{
		throw invalid_argument("Unsupported version");
	}
}

UsernamePasswdReqOption::UsernamePasswdReqOption(const string_view &username, const string_view &passwd)
	: AuthDataOption(SOCKS6_METHOD_USRPASSWD), req(username, passwd) {}

struct RawUsrPasswdReply
{
	SOCKS6AuthDataOption authDataOptionHead;
	
	uint8_t version;
	uint8_t status;
	
	uint8_t padding[1];
} __attribute__((packed));

void UsernamePasswdReplyOption::fill(uint8_t *buf) const
{
	AuthDataOption::fill(buf);
	
	RawUsrPasswdReply *opt = reinterpret_cast<RawUsrPasswdReply *>(buf);
	
	opt->version = SOCKS6_PWAUTH_VERSION;
	opt->status = !success;
	opt->padding[0] = 0;
}

size_t UsernamePasswdReplyOption::packedSize() const
{
	return sizeof(RawUsrPasswdReply);
}

void UsernamePasswdReplyOption::incrementalParse(SOCKS6AuthDataOption *baseOpt, OptionSet *optionSet)
{
	RawUsrPasswdReply *opt = rawOptCast<RawUsrPasswdReply>(baseOpt, false);
	
	if (opt->version != SOCKS6_PWAUTH_VERSION)
		throw BadVersionException(opt->version);
	
	bool success = !opt->status;
	
	optionSet->userPassword.setReply(success);
}

}
