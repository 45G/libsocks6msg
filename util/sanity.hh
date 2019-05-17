#ifndef SOCKS6MSG_SANITY_HH
#define SOCKS6MSG_SANITY_HH

#pragma GCC diagnostic error "-Wswitch"

#include "socks6.h"
#include "exceptions.hh"

namespace S6M
{

template <typename ENUM>
ENUM enumCast(int val)
{
	/* fail if instantiated */
	switch ((ENUM)val) {}
}

template <>
SOCKS6StackLeg enumCast<SOCKS6StackLeg>(int val);

template <>
SOCKS6TokenExpenditureCode enumCast<SOCKS6TokenExpenditureCode>(int val);

template <>
SOCKS6RequestCode enumCast<SOCKS6RequestCode>(int val);

template <>
SOCKS6OperationReplyCode enumCast<SOCKS6OperationReplyCode>(int val);

template <>
SOCKS6AuthReplyCode enumCast<SOCKS6AuthReplyCode>(int val);

template <>
SOCKS6SessionType enumCast<SOCKS6SessionType>(int val);

template <>
SOCKS6AddressType enumCast<SOCKS6AddressType>(int val);

template <>
SOCKS6MPAvailability enumCast<SOCKS6MPAvailability>(int val);

void tokenWindowSanity(uint32_t winSize);

}

#endif // SOCKS6MSG_SANITY_HH
