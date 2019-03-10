#include "sessionoption.hh"

namespace S6M
{

void S6M::SessionOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6SessionOption *opt = reinterpret_cast<SOCKS6SessionOption *>(buf);
	
	opt->type = getType();
}

void SessionOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6SessionOption *opt = (SOCKS6SessionOption *)buf;
	
	if (optionLen < sizeof(SOCKS6SessionOption))
		throw InvalidFieldException();
	
	switch (opt->type)
	{
	case SOCKS6_SESSION_REQUEST:
		SessionRequestOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_SESSION_TEARDOWN:
		SessionTeardownOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_SESSION_TICKET:
		SessionTicketOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_SESSION_OK:
		SessionOKOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_SESSION_INEXISTENT:
		SessionInexistentOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	case SOCKS6_SESSION_TICKET_UPDATE:
		SessionTicketUpdateOption::incementalParse(buf, optionLen, optionSet);
		break;
		
	default:
		throw InvalidFieldException();
	}
}

size_t SessionRequestOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionRequestOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

size_t SessionTeardownOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionTeardownOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

void SessionTicketOption::fill(uint8_t *buf) const
{
	
}

size_t SessionTicketOption::packedSize() const
{
	
}

void SessionTicketOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

size_t SessionOKOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionOKOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

size_t SessionInexistentOption::packedSize() const
{
	return sizeof(SOCKS6SessionOption);
}

void SessionInexistentOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

void SessionTicketUpdateOption::fill(uint8_t *buf) const
{
	
}

size_t SessionTicketUpdateOption::packedSize() const
{
	
}

void SessionTicketUpdateOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	
}

}
