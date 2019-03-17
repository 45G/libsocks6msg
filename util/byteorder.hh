#ifndef SOCKS6MSG_BYTEORDER_HH
#define SOCKS6MSG_BYTEORDER_HH

#include <arpa/inet.h>

namespace S6M
{

template <typename T> T hton(T x)
{
	static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4, "Bad integer size");
	
	if (sizeof (T) == 1)
		return x;
	else if (sizeof (T) == 2)
		return htons(x);
	else if (sizeof (T) == 4)
		return htonl(x);
}

template <typename T> T ntoh(T x)
{
	static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4, "Bad integer size");
	
	if (sizeof (T) == 1)
		return x;
	else if (sizeof (T) == 2)
		return ntohs(x);
	else if (sizeof (T) == 4)
		return ntohl(x);
}

}

#endif // SOCKS6MSG_BYTEORDER_HH
