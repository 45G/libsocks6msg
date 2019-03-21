#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <stdint.h>
#include <stdexcept>

namespace S6M
{

class BadVersionException: public std::runtime_error
{
	uint8_t maj;
	uint8_t min;
	
public:
	BadVersionException(uint8_t major, uint8_t minor = 0)
		: runtime_error("Unsupported protocol version"), maj(major), min(minor) {}
	
	uint8_t getMajor() const
	{
		return maj;
	}
	
	uint8_t getMinor() const
	{
		return min;
	}
};

class EndOfBufferException: public std::length_error
{
public:
	EndOfBufferException()
		: length_error("End of buffer") {}
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
