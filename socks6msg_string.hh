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
	
	String(ByteBuffer *bb, bool nonEmpty = true);
	
	size_t packedSize()
	{
		return 1 + str.length();
	}
	
	void pack(ByteBuffer *bb);
	
	std::string getStr() const
	{
		return str;
	}
};

}

#endif // SOCKS6MSG_STRING_HH
