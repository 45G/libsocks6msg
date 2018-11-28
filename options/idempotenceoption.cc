#include <arpa/inet.h>
#include "idempotenceoption.hh"
#include "../socks6msg_optionset.hh"
#include "../util/sanity.hh"

namespace S6M
{

void IdempotenceOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

void IdempotenceOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (opt->optionHead.len < sizeof (SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		TokenWindowRequestOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		TokenWindowAdvertOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		TokenExpenditureRequestOption::incementalParse(buf, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		TokenExpenditureReplyOption::incementalParse(buf, optionSet);
		break;
	}
	
	throw InvalidFieldException();
}

void TokenWindowRequestOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	opt->windowSize = htonl(winSize);
}

size_t TokenWindowRequestOption::packedSize() const
{
	return sizeof(SOCKS6WindowRequestOption);
}

void TokenWindowRequestOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowRequestOption))
		throw InvalidFieldException();
	
	uint32_t winSize = ntohl(opt->windowSize);
	
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	optionSet->requestTokenWindow(winSize);
}

TokenWindowRequestOption::TokenWindowRequestOption(uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_REQ), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
}

size_t TokenWindowAdvertOption::packedSize() const
{
	return sizeof(SOCKS6WindowAdvertOption);
}

void TokenWindowAdvertOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	opt->windowBase = htonl(winBase);
	opt->windowSize = htonl(winSize);
}

void TokenWindowAdvertOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6WindowAdvertOption))
		throw InvalidFieldException();
	
	uint32_t winBase = ntohl(opt->windowBase);
	uint32_t winSize = ntohl(opt->windowSize);
	
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
	
	optionSet->setTokenWindow(winBase, winSize);
}

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw InvalidFieldException();
}

size_t TokenExpenditureRequestOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureOption);
}

void TokenExpenditureRequestOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	opt->token = htonl(token);
}

void TokenExpenditureRequestOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureOption))
		throw InvalidFieldException();
	
	optionSet->setToken(ntohl(opt->token));
}

size_t TokenExpenditureReplyOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureReplyOption);
}

void TokenExpenditureReplyOption::fill(uint8_t *buf) const
{
	IdempotenceOption::fill(buf);
	
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	opt->code = code;
}

void TokenExpenditureReplyOption::incementalParse(void *buf, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (opt->idempotenceOptionHead.optionHead.len != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw InvalidFieldException();
	
	optionSet->setExpenditureReply(enumCast<SOCKS6TokenExpenditureCode>(opt->code));
}

}
