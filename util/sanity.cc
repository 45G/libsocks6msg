#include <stdexcept>
#include "sanity.hh"

#pragma GCC diagnostic error "-Wswitch"

using namespace std;

namespace S6M
{

template <>
SOCKS6MPTCPScheduler enumCast<SOCKS6MPTCPScheduler>(int val)
{
	SOCKS6MPTCPScheduler conv = (SOCKS6MPTCPScheduler)val;
	
	switch (conv)
	{
	case SOCKS6_MPTCP_SCHEDULER_LOWEST_LATENCY_FIRST:
	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		return conv;
	}
	
	throw invalid_argument("Bad MPTCP Scheduler");
}

template <>
SOCKS6StackLeg enumCast<SOCKS6StackLeg>(int val)
{
	SOCKS6StackLeg conv = (SOCKS6StackLeg)val;
	
	switch (conv)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
	case SOCKS6_STACK_LEG_BOTH:
		return conv;
	}
	
	throw invalid_argument("Bad leg");
}

template <>
SOCKS6TokenExpenditureCode enumCast<SOCKS6TokenExpenditureCode>(int val)
{
	SOCKS6TokenExpenditureCode conv = (SOCKS6TokenExpenditureCode)val;
	
	switch (conv)
	{
	case SOCKS6_TOK_EXPEND_SUCCESS:
	case SOCKS6_TOK_EXPEND_NO_WND:
	case SOCKS6_TOK_EXPEND_OUT_OF_WND:
	case SOCKS6_TOK_EXPEND_DUPLICATE:
		return conv;
	}
	
	throw invalid_argument("Bad token expenditure code");
}

template <>
SOCKS6RequestCode enumCast<SOCKS6RequestCode>(int val)
{
	SOCKS6RequestCode conv = (SOCKS6RequestCode)val;
	
	switch (conv)
	{
	case SOCKS6_REQUEST_NOOP:
	case SOCKS6_REQUEST_CONNECT:
	case SOCKS6_REQUEST_BIND:
	case SOCKS6_REQUEST_UDP_ASSOC:
		return conv;
	}
	
	throw invalid_argument("Bad request code");
}

template <>
SOCKS6OperationReplyCode enumCast<SOCKS6OperationReplyCode>(int val)
{
	SOCKS6OperationReplyCode conv = (SOCKS6OperationReplyCode)val;
	
	switch (conv)
	{
	case SOCKS6_OPERATION_REPLY_SUCCESS:
	case SOCKS6_OPERATION_REPLY_FAILURE:
	case SOCKS6_OPERATION_REPLY_NOT_ALLOWED:
	case SOCKS6_OPERATION_REPLY_NET_UNREACH:
	case SOCKS6_OPERATION_REPLY_HOST_UNREACH:
	case SOCKS6_OPERATION_REPLY_REFUSED:
	case SOCKS6_OPERATION_REPLY_TTL_EXPIRED:
	case SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED:
	case SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED:
	case SOCKS6_OPERATION_REPLY_TIMEOUT:
		return conv;
	}
	
	throw invalid_argument("Bad operation reply code");
}

template <>
SOCKS6AuthReplyCode enumCast<SOCKS6AuthReplyCode>(int val)
{
	SOCKS6AuthReplyCode conv = (SOCKS6AuthReplyCode)val;
	
	switch (conv)
	{
	case SOCKS6_AUTH_REPLY_SUCCESS:
	case SOCKS6_AUTH_REPLY_MORE:
		return conv;
	}
	
	throw invalid_argument("Bad authentication reply code");
}

template <>
SOCKS6SessionType enumCast<SOCKS6SessionType>(int val)
{
	SOCKS6SessionType conv = (SOCKS6SessionType)val;
	
	switch (conv)
	{
	case SOCKS6_SESSION_REQUEST:
	case SOCKS6_SESSION_ID:
	case SOCKS6_SESSION_TEARDOWN:
	case SOCKS6_SESSION_OK:
	case SOCKS6_SESSION_INVALID:
	case SOCKS6_SESSION_UNTRUSTED:
		return conv;
	}
	
	throw invalid_argument("Bad session option type");
}

template <>
SOCKS6AddressType enumCast<SOCKS6AddressType>(int val)
{
	SOCKS6AddressType conv = (SOCKS6AddressType)val;
	
	switch (conv)
	{
	case SOCKS6_ADDR_IPV4:
	case SOCKS6_ADDR_IPV6:
	case SOCKS6_ADDR_DOMAIN:
		return conv;
	}
	
	throw invalid_argument("Bad address type");
}


void tokenWindowSanity(uint32_t winSize)
{
	if (winSize < SOCKS6_TOKEN_WINDOW_MIN || winSize > SOCKS6_TOKEN_WINDOW_MAX)
		throw invalid_argument("Bad window size");
}

}
