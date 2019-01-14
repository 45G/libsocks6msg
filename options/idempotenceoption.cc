#include <arpa/inet.h>
#include "idempotenceoption.hh"
#include "optionset.hh"
#include "sanity.hh"

namespace S6M
{

void IdempotenceOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

void IdempotenceOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	if (optionLen < sizeof (SOCKS6IdempotenceOption))
		throw InvalidFieldException();
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		TokenWindowRequestOption::incementalParse(buf, optionLen, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		TokenWindowAdvertOption::incementalParse(buf, optionLen, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		TokenExpenditureRequestOption::incementalParse(buf, optionLen, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		TokenExpenditureReplyOption::incementalParse(buf, optionLen, optionSet);
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

void TokenWindowRequestOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	if (optionLen != sizeof(SOCKS6WindowRequestOption))
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

void TokenWindowAdvertOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	if (optionLen != sizeof(SOCKS6WindowAdvertOption))
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

void TokenExpenditureRequestOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	if (optionLen != sizeof(SOCKS6TokenExpenditureOption))
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

void TokenExpenditureReplyOption::incementalParse(void *buf, size_t optionLen, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureReplyOption *opt = reinterpret_cast<SOCKS6TokenExpenditureReplyOption *>(buf);
	
	if (optionLen != sizeof(SOCKS6TokenExpenditureReplyOption))
		throw InvalidFieldException();
	
	optionSet->setExpenditureReply(enumCast<SOCKS6TokenExpenditureCode>(opt->code));
}

}
