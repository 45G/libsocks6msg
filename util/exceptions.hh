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

class BadAddressTypeException: public std::invalid_argument
{
public:
	BadAddressTypeException()
		: invalid_argument("Bad address type") {}
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
