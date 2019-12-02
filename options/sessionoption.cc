#include "sessionoption.hh"
#include "optionset.hh"

using namespace std;

namespace S6M
{

void SessionRequestOption::simpleParse(OptionSet *optionSet)
{
	optionSet->session.request();
}

void SessionIDOption::fill(uint8_t *buf) const
{
	Option::fill(buf);

	SOCKS6SessionIDOption *opt = reinterpret_cast<SOCKS6SessionIDOption *>(buf);

	for (int i = 0; i < (int)id.size(); i++)
		opt->ticket[i] = id[i];
}

SessionIDOption::SessionIDOption(const std::vector<uint8_t> &ticket)
	: Option(SOCKS6_OPTION_SESSION_ID), id(ticket)
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
	return sizeof(SOCKS6SessionIDOption) + id.size();
}

void SessionIDOption::incrementalParse(SOCKS6Option *buf, OptionSet *optionSet)
{
	SOCKS6SessionIDOption *opt = rawOptCast<SOCKS6SessionIDOption>(buf);
	
	size_t idLen = ntohs(opt->optionHead.len) - sizeof(SOCKS6SessionIDOption);
	vector<uint8_t> id(opt->ticket, opt->ticket + idLen);
	optionSet->session.setID(move(id));
}

void SessionTeardownOption::simpleParse(OptionSet *optionSet)
{
	optionSet->session.tearDown();
}

void SessionOKOption::simpleParse(OptionSet *optionSet)
{
	optionSet->session.signalOK();
}

void SessionInvalidOption::simpleParse(OptionSet *optionSet)
{
	optionSet->session.signalReject();
}

void SessionUntrustedOption::simpleParse(OptionSet *optionSet)
{
	optionSet->session.setUntrusted();
}

}
