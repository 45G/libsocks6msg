#include <arpa/inet.h>
#include "idempotenceoption.hh"
#include "optionset.hh"
#include "sanity.hh"

using namespace std;

namespace S6M
{

void IdempotenceRequestOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6WindowRequestOption *opt = reinterpret_cast<SOCKS6WindowRequestOption *>(buf);
	
	opt->windowSize = htonl(winSize);
}

size_t IdempotenceRequestOption::packedSize() const
{
	return sizeof(SOCKS6WindowRequestOption);
}

void IdempotenceRequestOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6WindowRequestOption *opt = rawOptCast<SOCKS6WindowRequestOption>(optBase, false);
	
	uint32_t winSize = ntohl(opt->windowSize);
	
	optionSet->idempotence.request(winSize);
}

size_t IdempotenceWindowOption::packedSize() const
{
	return sizeof(SOCKS6WindowAdvertOption);
}

void IdempotenceWindowOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6WindowAdvertOption *opt = reinterpret_cast<SOCKS6WindowAdvertOption *>(buf);
	
	opt->windowBase = htonl(winBase);
	opt->windowSize = htonl(winSize);
}

void IdempotenceWindowOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6WindowAdvertOption *opt = rawOptCast<SOCKS6WindowAdvertOption>(optBase, false);
	
	uint32_t winBase = ntohl(opt->windowBase);
	uint32_t winSize = ntohl(opt->windowSize);
	
	optionSet->idempotence.advertise(winBase, winSize);
}

size_t IdempotenceExpenditureOption::packedSize() const
{
	return sizeof(SOCKS6TokenExpenditureOption);
}

void IdempotenceExpenditureOption::fill(uint8_t *buf) const
{
	Option::fill(buf);
	
	SOCKS6TokenExpenditureOption *opt = reinterpret_cast<SOCKS6TokenExpenditureOption *>(buf);
	
	opt->token = htonl(token);
}

void IdempotenceExpenditureOption::incrementalParse(SOCKS6Option *optBase, OptionSet *optionSet)
{
	SOCKS6TokenExpenditureOption *opt = rawOptCast<SOCKS6TokenExpenditureOption>(optBase, false);
	
	optionSet->idempotence.setToken(ntohl(opt->token));
}

void IdempotenceAcceptedOption::simpleParse(OptionSet *optionSet)
{
	optionSet->idempotence.setReply(true);
}

void IdempotenceRejectedOption::simpleParse(OptionSet *optionSet)
{
	optionSet->idempotence.setReply(false);
}

}
