#ifndef SOCKS6MSG_BASE_HH
#define SOCKS6MSG_BASE_HH

#include <exception>
#include <stdint.h>
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

class ByteBuffer
{
	uint8_t *buf;
	size_t used;
	size_t totalSize;
	
public:
	ByteBuffer(uint8_t *buf, size_t size)
		: buf(buf), used(0), totalSize(size) {}
	
	uint8_t *getBuf() const
	{
		return buf;
	}
	
	size_t getUsed() const
	{
		return used;
	}
	
	
	size_t getTotalSize() const
	{
		return totalSize;
	}
	
	template <typename T> T *get(size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw Exception(S6M_ERR_BUFFER);
		
		T *ret = reinterpret_cast<T *>(buf + used);
		used += req;
		return ret;
	}
	
	template <typename T> void put(T *what, size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw Exception(S6M_ERR_BUFFER);
		
		memcpy(buf + used, what, req);
		used += req;
	}
};

}

#endif // SOCKS6MSG_BASE_HH
