#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <stdint.h>
#include <stdexcept>

namespace S6M
{

class Exception: public std::exception
{
public:
	const char *what() const throw () = 0;
};

class BadVersionException: public Exception
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

//TODO: get rid of this
class InvalidFieldException: public std::invalid_argument
{
public:
	InvalidFieldException()
		: std::invalid_argument("") {}
};

class EndOfBufferException: public Exception
{
public:
	const char *what() const throw ();
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
