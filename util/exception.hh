#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <stdint.h>
#include <stdexcept>

namespace S6M
{

class BadVersionException: public std::exception
{
	uint8_t maj;
	uint8_t min;
	
public:
	BadVersionException(uint8_t major, uint8_t minor = 0)
		: maj(major), min(minor) {}
	
	const char *what() const throw ();
	
	uint8_t getMajor() const
	{
		return maj;
	}
	
	uint8_t getMinor() const
	{
		return min;
	}
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
