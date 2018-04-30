#ifndef SOCKS6MSG_EXCEPTION_HH
#define SOCKS6MSG_EXCEPTION_HH

#include <exception>

namespace S6M
{

class Exception: std::exception
{
public:
	Exception()
	{
		//TODO
	}

	//const char *what() const;
};

class BadVersionException: Exception
{
	//TODO
};

class InvalidFieldException: Exception
{
	//TODO
};

class EndOfBufferException: Exception
{
	//TODO
};

}

#endif // SOCKS6MSG_EXCEPTION_HH
