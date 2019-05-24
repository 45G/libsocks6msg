#ifndef SOCKS6MSG_RESTRICTEDINT_HH
#define SOCKS6MSG_RESTRICTEDINT_HH

#include <stdint.h>
#include <stdexcept>
#include "socks6.h"

namespace S6M
{

template <typename T, T MIN, T MAX>
class BoundedInt
{
	T value;
	
public:
	BoundedInt()
		: value(MIN) {}
	
	BoundedInt(T value)
		: value(value)
	{
		static_assert (MIN <= MAX, "MIN must be le MAX");
		if (value < MIN || value > MAX)
			throw std::range_error("Value out of bounds");
	}
	
	operator T () const
	{
		return value;
	}
};

class OptionsLength: public BoundedInt<uint16_t, 0, SOCKS6_OPTIONS_LENGTH_MAX>
{
public:
	OptionsLength(uint16_t value)
		: BoundedInt(value)
	{
		if (value % SOCKS6_ALIGNMENT != 0)
			throw std::invalid_argument("Number must be multiple of 4");
	}
};

}

#endif // SOCKS6MSG_RESTRICTEDINT_HH
