#ifndef S6M_PADDED_HH
#define S6M_PADDED_HH

#include <cstring>
#include <bytebuffer.hh>

namespace S6M
{

template <typename T, int HEAD_START = 0>
class Padded: public T
{
	static const int ALIGN = 4;
	
public:
	using T::T;
	
	size_t paddingSize() const
	{
		return (ALIGN - (T::packedSize() + HEAD_START) % ALIGN) % ALIGN;
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

#endif // S6M_PADDED_HH