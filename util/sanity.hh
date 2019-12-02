#ifndef SOCKS6MSG_SANITY_HH
#define SOCKS6MSG_SANITY_HH

#include "socks6.h"
#include "exceptions.hh"

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"

namespace S6M
{

template <typename ENUM>
inline ENUM enumCast(int val)
{
	/* fail if instantiated */
	switch ((ENUM)val) {}
}

template <>
inline SOCKS6StackLeg enumCast<SOCKS6StackLeg>(int val)
{
	SOCKS6StackLeg conv = (SOCKS6StackLeg)val;

	switch (conv)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
	case SOCKS6_STACK_LEG_BOTH:
		return conv;
	}

	throw std::invalid_argument("Bad leg");
}

template <>
inline SOCKS6AuthReplyCode enumCast<SOCKS6AuthReplyCode>(int val)
{
	SOCKS6AuthReplyCode conv = (SOCKS6AuthReplyCode)val;

	switch (conv)
	{
	case SOCKS6_AUTH_REPLY_SUCCESS:
	case SOCKS6_AUTH_REPLY_FAILURE:
		return conv;
	}

	throw std::invalid_argument("Bad authentication reply code");
}

template<>
inline SOCKS6MPAvailability enumCast<SOCKS6MPAvailability>(int val)
{
	SOCKS6MPAvailability conv = (SOCKS6MPAvailability)val;

	switch (conv)
	{
	case SOCKS6_MP_AVAILABLE:
	case SOCKS6_MP_UNAVAILABLE:
		return conv;
	}

	throw std::invalid_argument("Bad MP availability");
}

#pragma GCC diagnostic pop

template <typename ENUM>
class Enum
{
	ENUM val;

public:
	Enum(int val)
		: val(enumCast<ENUM>(val)) {}

	operator ENUM() const
	{
		return val;
	}
};

}

#endif // SOCKS6MSG_SANITY_HH
