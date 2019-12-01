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
	static_assert (MIN <= MAX, "MIN must be le MAX");
	
	T value;
	
public:
	BoundedInt()
		: value(MIN) {}
	
	BoundedInt(T value)
		: value(value)
	{
		if (value < MIN || value > MAX)
			throw std::range_error("Value out of bounds");
	}
	
	operator T () const
	{
		return value;
	}
};

}

#endif // SOCKS6MSG_RESTRICTEDINT_HH
