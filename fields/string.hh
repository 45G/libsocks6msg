#ifndef SOCKS6MSG_STRING_HH
#define SOCKS6MSG_STRING_HH

#include <string>
#include <vector>
#include <memory>
#include "../util/bytebuffer.hh"

namespace S6M
{

class String
{
	std::shared_ptr<std::string> str;
	
public:
	//TODO: get rid of this constructor
	String() {}
	
	String(const std::shared_ptr<std::string> str);
	
	String(ByteBuffer *bb);
	
	size_t packedSize() const
	{
		return 1 + str->length();
	}
	
	void pack(ByteBuffer *bb) const;
	
	const std::shared_ptr<std::string> getStr() const
	{
		return str;
	}
};

}

#endif // SOCKS6MSG_STRING_HH
