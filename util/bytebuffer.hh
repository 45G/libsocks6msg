#ifndef SOCKS6MSG_BYTEBUFFER_HH
#define SOCKS6MSG_BYTEBUFFER_HH

#include <stdint.h>
#include <unistd.h>
#include "exceptions.hh"

namespace S6M
{

class ByteBuffer
{
	uint8_t *buf;
	size_t  used;
	size_t  totalSize;
	
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
	
	template <typename T>
	T *peek(size_t count = 1)
	{
		size_t req = sizeof(T) * count;

		if (req + used > totalSize)
			throw EndOfBufferException();

		T *ret = reinterpret_cast<T *>(buf + used);
		return ret;
	}

	template <typename T>
	T *get(size_t count = 1)
	{
		T *ret = peek<T>(count);
		used += sizeof(T) * count;
		return ret;
	}
	
	template <typename T>
	void put(T *what, size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw EndOfBufferException();
		
		memcpy(buf + used, what, req);
		used += req;
	}
};

}

#endif // SOCKS6MSG_BYTEBUFFER_HH
