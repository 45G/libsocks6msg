#include "sessionoption.hh"
#include "optionset.hh"

using namespace std;

namespace S6M
{

size_t SessionRequestOption::packedSize() const
{
	return sizeof(SOCKS6Option);
}

void SessionRequestOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6Option>(optBase, false);
	optionSet->session.request();
}

void SessionIDOption::fill(uint8_t *buf) const
{
	Option::fill(buf);

	SOCKS6SessionIDOption *opt = reinterpret_cast<SOCKS6SessionIDOption *>(buf);

	for (int i = 0; i < (int)ticket.size(); i++)
		opt->ticket[i] = ticket[i];
}

SessionIDOption::SessionIDOption(const std::vector<uint8_t> &ticket)
	: Option(SOCKS6_OPTION_SESSION_ID), ticket(ticket)
{
	//TODO: convert to length_error
	if (ticket.size() == 0)
		throw invalid_argument("No ID");
	if (ticket.size() % 4 > 0)
		throw invalid_argument("Bad ID length");
	if (packedSize() > SOCKS6_ID_LENGTH_MAX)
		throw invalid_argument("ID is too large");
}

size_t SessionIDOption::packedSize() const
{
	return sizeof(SOCKS6SessionIDOption) + ticket.size();
}

void SessionIDOption::incrementalParse(SOCKS6Option *buf, OptionSet *optionSet)
{
	SOCKS6SessionIDOption *opt = rawOptCast<SOCKS6SessionIDOption>(buf);
	
	size_t ticketLen = ntohs(opt->optionHead.len) - sizeof(SOCKS6SessionIDOption);
	vector<uint8_t> ticket(opt->ticket, opt->ticket + ticketLen);
	optionSet->session.setID(move(ticket));
}

size_t SessionTeardownOption::packedSize() const
{
	return sizeof(SOCKS6Option);
}

void SessionTeardownOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6Option>(optBase, false);
	optionSet->session.tearDown();
}

size_t SessionOKOption::packedSize() const
{
	return sizeof(SOCKS6Option);
}

void SessionOKOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6Option>(optBase, false);
	optionSet->session.signalOK();
}

size_t SessionInvalidOption::packedSize() const
{
	return sizeof(SOCKS6Option);
}

void SessionInvalidOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6Option>(optBase, false);
	optionSet->session.signalReject();
}

size_t SessionUntrustedOption::packedSize() const
{
	return sizeof(SOCKS6Option);
}

void SessionUntrustedOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6Option>(optBase, false);
	optionSet->session.setUntrusted();
}

}
