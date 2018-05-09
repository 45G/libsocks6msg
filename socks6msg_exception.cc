#include "socks6msg_exception.hh"

namespace S6M
{

const char *BadVersionException::what() const throw ()
{
	return "Unsupported protocol version";
}

const char *InvalidFieldException::what() const throw ()
{
	return "Invalid field";
}

const char *EndOfBufferException::what() const throw ()
{
	return "End of buffer";
}

}
