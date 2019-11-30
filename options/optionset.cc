#include "optionset.hh"

using namespace std;

namespace S6M
{

OptionSet::OptionSet(ByteBuffer *bb, Mode mode, uint16_t optionsLength)
	: OptionSetBase(this, mode)
{
	if (optionsLength > SOCKS6_OPTIONS_LENGTH_MAX)
		throw invalid_argument("Bad options length");
	ByteBuffer optsBB(bb->get<uint8_t>(optionsLength), optionsLength);
	
	while (optsBB.getUsed() < optsBB.getTotalSize())
	{
		SOCKS6Option *opt;

		try
		{
			opt = optsBB.get<SOCKS6Option>();

			/* bad option length wrecks remaining options */
			size_t optLen = ntohs(opt->len);
			if (optLen < sizeof(SOCKS6Option))
				throw length_error("Option too short");
			if (optLen % SOCKS6_ALIGNMENT != 0)
				throw length_error("Option not aligned");

			optsBB.get<uint8_t>(optLen - sizeof(SOCKS6Option));
		}
		catch (length_error &)
		{
			break;
		}
		
		try
		{
			Option::incrementalParse(opt, this);
		}
		catch (invalid_argument &) {}
	}
}

void UserPasswdOptionSet::setCredentials(const string &user, const string &passwd)
{
	enforceMode(M_REQ);
	commit(req, [&]() { return UsernamePasswdReqOption(user, passwd); });
}

void UserPasswdOptionSet::setReply(bool success)
{
	enforceMode(M_AUTH_REP);
	commit(reply, [=]() { return UsernamePasswdReplyOption(success); });
}

void AuthMethodOptionSet::advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
{
	enforceMode(M_REQ);
	commit(advertOption, [&]() { return AuthMethodAdvertOption(initialDataLen, methods); });
}

void AuthMethodOptionSet::select(SOCKS6Method method)
{
	enforceMode(M_AUTH_REP);
	commit(selectOption, [=]() { return AuthMethodSelectOption(method); });
}

}
