#include "sanity.hh"
#include "exceptions.hh"

#pragma GCC diagnostic error "-Wswitch"

using namespace std;

namespace S6M
{

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
	case SOCKS6_AUTH_REPLY_FAILURE:
		return conv;
	}
	
	throw invalid_argument("Bad authentication reply code");
}

template<>
SOCKS6MPAvailability enumCast<SOCKS6MPAvailability>(int val)
{
	SOCKS6MPAvailability conv = (SOCKS6MPAvailability)val;

	switch (conv)
	{
	case SOCKS6_MP_AVAILABLE:
	case SOCKS6_MP_UNAVAILABLE:
		return conv;
	}

	throw invalid_argument("Bad MP availability");
}

}
