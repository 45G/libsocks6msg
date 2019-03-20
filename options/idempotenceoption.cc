#include <arpa/inet.h>
#include "idempotenceoption.hh"
#include "optionset.hh"
#include "sanity.hh"

using namespace std;

namespace S6M
{

void IdempotenceOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6IdempotenceOption *opt = reinterpret_cast<SOCKS6IdempotenceOption *>(buf);
	
	opt->type = type;
}

void IdempotenceOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6IdempotenceOption *opt = rawOptCast<SOCKS6IdempotenceOption>(optBase);
	
	switch ((SOCKS6IDempotenceType)opt->type)
	{
	case SOCKS6_IDEMPOTENCE_WND_REQ:
		TokenWindowRequestOption::incrementalParse(opt, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_WND_ADVERT:
		TokenWindowAdvertOption::incrementalParse(opt, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND:
		TokenExpenditureRequestOption::incrementalParse(opt, optionSet);
		break;
	
	case SOCKS6_IDEMPOTENCE_TOK_EXPEND_REPLY:
		TokenExpenditureReplyOption::incrementalParse(opt, optionSet);
		break;
		
	default:
		throw invalid_argument("Unknown type");
	}
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

void TokenWindowRequestOption::incrementalParse(SOCKS6IdempotenceOption *optBase, OptionSet *optionSet)
{
	SOCKS6WindowRequestOption *opt = rawOptCast<SOCKS6WindowRequestOption>(optBase, false);
	
	uint32_t winSize = ntohl(opt->windowSize);
	tokenWindowSanity(winSize);
	
	optionSet->requestTokenWindow(winSize);
}

TokenWindowRequestOption::TokenWindowRequestOption(uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_REQ), winSize(winSize)
{
	tokenWindowSanity(winSize);
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

void TokenWindowAdvertOption::incrementalParse(SOCKS6IdempotenceOption *optBase, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = rawOptCast<SOCKS6WindowAdvertOption>(optBase, false);
	
	uint32_t winBase = ntohl(opt->windowBase);
	uint32_t winSize = ntohl(opt->windowSize);
	
	tokenWindowSanity(winSize);
	
	optionSet->setTokenWindow(winBase, winSize);
}

TokenWindowAdvertOption::TokenWindowAdvertOption(uint32_t winBase, uint32_t winSize)
	: IdempotenceOption(SOCKS6_IDEMPOTENCE_WND_ADVERT), winBase(winBase), winSize(winSize)
{
	tokenWindowSanity(winSize);
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

void TokenExpenditureRequestOption::incrementalParse(SOCKS6IdempotenceOption *optBase, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = rawOptCast<SOCKS6TokenExpenditureOption>(optBase, false);
	
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

void TokenExpenditureReplyOption::incrementalParse(SOCKS6IdempotenceOption *optBase, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureReplyOption *opt = rawOptCast<SOCKS6TokenExpenditureReplyOption>(optBase, false);
	
	optionSet->setExpenditureReply(enumCast<SOCKS6TokenExpenditureCode>(opt->code));
}

}
