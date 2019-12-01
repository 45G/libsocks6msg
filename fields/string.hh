#ifndef SOCKS6MSG_STRING_HH
#define SOCKS6MSG_STRING_HH

#include <string.h>
#include <string>
#include <vector>
#include <memory>
#include "bytebuffer.hh"

namespace S6M
{

class String
{
	std::string str;
	
	void sanity()
	{
		if (str.length() == 0)
			throw std::invalid_argument("Empty string");
		if (str.length() > 255)
			throw std::invalid_argument("String too long");
		if (str.find_first_of('\0') != std::string::npos)
			throw std::invalid_argument("NUL in string");
	}
	
public:
	String(const std::string &str)
		: str(str)
	{
		sanity();
	}
	
	String(ByteBuffer *bb)
	{
		uint8_t *len = bb->get<uint8_t>();
		uint8_t *rawStr = bb->get<uint8_t>(*len);
		
		str = std::string(reinterpret_cast<const char *>(rawStr), (size_t)*len);
		
		sanity();
	}
	
	size_t packedSize() const
	{
		return 1 + str.length();
	}
	
	void pack(ByteBuffer *bb) const
	{
		uint8_t *len = bb->get<uint8_t>();
		uint8_t *rawStr = bb->get<uint8_t>(str.length());
		
		*len = str.length();
		memcpy(rawStr, str.c_str(), *len);
	}
	
	const std::string *getStr() const
	{
		return &str;
	}
};

}

#endif // SOCKS6MSG_STRING_HH
