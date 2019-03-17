#include "sessionoption.hh"
#include "optionset.hh"

using namespace std;

namespace S6M
{

void S6M::SessionOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6SessionOption *opt = reinterpret_cast<SOCKS6SessionOption *>(buf);
	
	opt->type = getType();
}

void SessionOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6SessionOption *opt = rawOptCast<SOCKS6SessionOption>(optBase);
	
	switch (opt->type)
	{
	case SOCKS6_SESSION_REQUEST:
		SessionRequestOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_TEARDOWN:
		SessionTeardownOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_ID:
		SessionIDOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_OK:
		SessionOKOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_INVALID:
		SessionInvalidOption::incrementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_UNTRUSTED:
		SessionUntrustedOption::incrementalParse(opt, optionSet);
		break;
		
	default:
		throw invalid_argument("Unknown type");
	}
}

size_t SessionRequestOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionRequestOption::incrementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->request();
}

void SessionIDOption::fill(uint8_t *buf) const
{
	SessionOption::fill(buf);

	SOCKS6SessionIDOption *opt = reinterpret_cast<SOCKS6SessionIDOption *>(buf);

	for (int i = 0; i < (int)ticket.size(); i++)
		opt->ticket[i] = ticket[i];
}

SessionIDOption::SessionIDOption(const std::vector<uint8_t> &ticket)
	: SessionOption(SOCKS6_SESSION_ID), ticket(ticket)
{
	if (ticket.size() == 0)
		throw invalid_argument("No ticket");
	if (packedSize() > SOCKS6_ID_LENGTH_MAX)
		throw invalid_argument("Ticket is too large");
}

size_t SessionIDOption::packedSize() const
{
	return sizeof(SOCKS6SessionIDOption) + ticket.size();
}

void SessionIDOption::incrementalParse(SOCKS6SessionOption *buf, OptionSet *optionSet)
{
	SOCKS6SessionIDOption *opt = rawOptCast<SOCKS6SessionIDOption>(buf);
	
	size_t ticketLen = ntohs(buf->optionHead.len) - sizeof(SOCKS6SessionIDOption);
	vector<uint8_t> ticket(opt->ticket, opt->ticket + ticketLen);
	optionSet->session()->setID(move(ticket));
}

size_t SessionTeardownOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionTeardownOption::incrementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->tearDown();
}

size_t SessionOKOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionOKOption::incrementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->signalOK();
}

size_t SessionInvalidOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionInvalidOption::incrementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->signalReject();
}

size_t SessionUntrustedOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionUntrustedOption::incrementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->setUntrusted();
}

}
