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

void SessionOption::incementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6SessionOption *opt = rawOptCast<SOCKS6SessionOption>(optBase);
	
	switch (opt->type)
	{
	case SOCKS6_SESSION_REQUEST:
		SessionRequestOption::incementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_TEARDOWN:
		SessionTeardownOption::incementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_TICKET:
		SessionTicketOption::incementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_OK:
		SessionOKOption::incementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_REJECT:
		SessionRejectOption::incementalParse(opt, optionSet);
		break;
		
	case SOCKS6_SESSION_UPDATE:
		SessionUpdateOption::incementalParse(opt, optionSet);
		break;
		
	default:
		throw invalid_argument("Unknown type");
	}
}

size_t SessionRequestOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionRequestOption::incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->request();
}

size_t SessionTeardownOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionTeardownOption::incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->tearDown();
}

void SessionTicketOption::fill(uint8_t *buf) const
{
	SessionOption::fill(buf);

	SOCKS6SessionTicketOption *opt = reinterpret_cast<SOCKS6SessionTicketOption *>(buf);

	for (int i = 0; i < (int)ticket.size(); i++)
		opt->ticket[i] = ticket[i];
}

SessionTicketOption::SessionTicketOption(const std::vector<uint8_t> &ticket)
	: SessionOption(SOCKS6_SESSION_TICKET), ticket(ticket)
{
	if (ticket.size() == 0)
		throw invalid_argument("No ticket");
	if (packedSize() > SOCKS6_TICKET_LENGTH_MAX)
		throw invalid_argument("Ticket is too large");
}

size_t SessionTicketOption::packedSize() const
{
	return sizeof(SOCKS6SessionTicketOption) + ticket.size();
}

void SessionTicketOption::incementalParse(SOCKS6SessionOption *buf, OptionSet *optionSet)
{
	SOCKS6SessionTicketOption *opt = rawOptCast<SOCKS6SessionTicketOption>(buf);
	
	size_t ticketLen = ntohs(buf->optionHead.len) - sizeof(SOCKS6SessionTicketOption);
	vector<uint8_t> ticket(opt->ticket, opt->ticket + ticketLen);
	optionSet->session()->echoTicket(move(ticket));
}

size_t SessionOKOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionOKOption::incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->signalOK();
}

size_t SessionRejectOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionRejectOption::incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	rawOptCast<SOCKS6SessionOption>(optBase, false);
	optionSet->session()->signalReject();
}

void SessionUpdateOption::fill(uint8_t *buf) const
{
	SessionOption::fill(buf);

	SOCKS6SessionTicketUpdateOption *opt = reinterpret_cast<SOCKS6SessionTicketUpdateOption *>(buf);

	opt->version = htons(version);
	for (int i = 0; i < (int)ticket.size(); i++)
		opt->ticket[i] = ticket[i];
}

SessionUpdateOption::SessionUpdateOption(const std::vector<uint8_t> &ticket, uint16_t version)
	: SessionOption(SOCKS6_SESSION_UPDATE), ticket(ticket), version(version)
{
	if (ticket.size() == 0)
		throw invalid_argument("No ticket");
	if (packedSize() > SOCKS6_TICKET_LENGTH_MAX)
		throw invalid_argument("Ticket is too large");
}

size_t SessionUpdateOption::packedSize() const
{
	return sizeof(SOCKS6SessionTicketUpdateOption) + ticket.size();
}

void SessionUpdateOption::incementalParse(SOCKS6SessionOption *optBase, OptionSet *optionSet)
{
	SOCKS6SessionTicketUpdateOption *opt = rawOptCast<SOCKS6SessionTicketUpdateOption>(optBase);
	
	uint16_t ticketVersion = ntohs(opt->version);
	size_t ticketLen = ntohs(optBase->optionHead.len) - sizeof(SOCKS6SessionTicketUpdateOption);
	vector<uint8_t> ticket(opt->ticket, opt->ticket + ticketLen);
	optionSet->session()->updateTicket(move(ticket), ticketVersion);
}

}
