#include "exception.hh"

namespace S6M
{

const char *BadVersionException::what() const throw ()
{
	return "Unsupported protocol version";
}

}
