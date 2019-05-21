#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <stdint.h>
#include <stdexcept>

namespace S6M
{

class BadVersionException: public std::runtime_error
{
	uint8_t version;
	
public:
	BadVersionException(uint8_t version)
		: runtime_error("Unsupported protocol version"), version(version) {}
	
	uint8_t getVersion() const
	{
		return version;
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
