#ifndef SOCKS6MSG_PADDED_HH
#define SOCKS6MSG_PADDED_HH

#include <cstring>
#include "socks6.h"
#include "bytebuffer.hh"

namespace S6M
{

static constexpr size_t paddingOf(size_t size)
{
	return (SOCKS6_ALIGNMENT - size % SOCKS6_ALIGNMENT) % SOCKS6_ALIGNMENT;
}

template <typename T, int HEAD_START = 0>
class Padded: public T
{
	static const int ALIGN = 4;
	
public:
	using T::T;
	
	size_t paddingSize() const
	{
		return paddingOf(T::packedSize() + HEAD_START);
	}
	
	Padded(ByteBuffer *bb)
		: T(bb)
	{
		bb->get<uint8_t>(paddingSize());
	}
	
	size_t packedSize() const
	{
		return T::packedSize() + paddingSize();
	}
	
	void pack(ByteBuffer *bb) const
	{
		T::pack(bb);
		
		uint8_t *padding = bb->get<uint8_t>(paddingSize());
		memset(padding, 0, paddingSize());
	}
};

}

#endif // SOCKS6MSG_PADDED_HH
