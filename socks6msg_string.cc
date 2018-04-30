#include <string.h>
#include "socks6msg_string.hh"

using namespace std;

namespace S6M
{

String::String(const string &str, bool nonEmpty)
	: str(str)
{
	if (nonEmpty && str.length() == 0)
		throw InvalidFieldException();
	
	if (str.length() > 255)
		throw InvalidFieldException();
	
	if (str.find_first_of('\0') != string::npos)
		throw InvalidFieldException();
}

String::String(ByteBuffer *bb, bool nonEmpty)
{
	uint8_t *len = bb->get<uint8_t>();
	
	if (nonEmpty && *len == 0)
		throw InvalidFieldException();
	
	uint8_t *rawStr = bb->get<uint8_t>(*len);
	
	str = string(reinterpret_cast<const char *>(rawStr), (size_t)*len);
	
	if (str.find_first_of('\0') != string::npos)
		throw InvalidFieldException();
}

void String::pack(ByteBuffer *bb) const
{
	uint8_t *len = bb->get<uint8_t>();
	uint8_t *rawStr = bb->get<uint8_t>(str.length());
	
	*len = str.length();
	memcpy(rawStr, str.c_str(), *len);
}

}
