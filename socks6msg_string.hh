#ifndef SOCKS6MSG_STRING_HH
#define SOCKS6MSG_STRING_HH

#include <string>
#include <vector>
#include "socks6msg_base.hh"

namespace S6M
{

class String
{
	std::string str;
	
public:
	String(const std::string &str, bool nonEmpty = true);
	
	String(const std::vector &data, bool nonEmpty = true)
		: String(std::string(data.data(), data.size()), nonEmpty) {}
	
	size_t packedSize()
	{
		return 1 + str.length();
	}
	
	String *parse(ByteBuffer *bb, bool nonEmpty = true);
	
	void pack(ByteBuffer *bb);
	
	std::string getStr() const
	{
		return str;
	}
};

}

#endif // SOCKS6MSG_STRING_HH
