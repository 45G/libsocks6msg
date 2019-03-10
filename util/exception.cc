#include "exception.hh"

namespace S6M
{

const char *BadVersionException::what() const throw ()
{
	return "Unsupported protocol version";
}

const char *EndOfBufferException::what() const throw ()
{
	return "End of buffer";
}

}
