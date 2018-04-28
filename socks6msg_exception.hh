#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <exception>
#include "socks6msg.h"

namespace S6M
{

class Exception: std::exception
{
	enum S6M_Error error;
	
public:
	Exception(enum S6M_Error error)
		: error(error) {}

	//const char *what() const;
	
	S6M_Error getError() const
	{
		return error;
	}
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
