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
		: error(error)
	{
		//nothing
	}

	//const char *what() const;
	
	S6M_Error getError() const
	{
		return error;
	}
};

class BadVersionException
{
	//TODO
};

class InvalidFieldException: Exception
{
	//TODO
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
