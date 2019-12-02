#ifndef SOCKS6MSG_SANITY_HH
#define SOCKS6MSG_SANITY_HH

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
SOCKS6AuthReplyCode enumCast<SOCKS6AuthReplyCode>(int val);

template <>
SOCKS6MPAvailability enumCast<SOCKS6MPAvailability>(int val);

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
