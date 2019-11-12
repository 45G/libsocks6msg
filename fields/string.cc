#include <string.h>
#include "string.hh"

using namespace std;

namespace S6M
{

String::String(std::shared_ptr<string> str)
	: str(str)
{
	if (str->length() == 0)
		throw invalid_argument("Empty string");
	
	if (str->length() > 255)
		throw invalid_argument("String too long");
	
	if (str->find_first_of('\0') != string::npos)
		throw invalid_argument("NUL in string");
}

String::String(ByteBuffer *bb)
{
	uint8_t *len = bb->get<uint8_t>();
	
	if (*len == 0)
		throw invalid_argument("Empty string");
	
	uint8_t *rawStr = bb->get<uint8_t>(*len);
	
	str = make_shared<string>(reinterpret_cast<const char *>(rawStr), (size_t)*len);
	
	if (str->find_first_of('\0') != string::npos)
		throw invalid_argument("NUL in string");
}

void String::pack(ByteBuffer *bb) const
{
	uint8_t *len = bb->get<uint8_t>();
	uint8_t *rawStr = bb->get<uint8_t>(str->length());
	
	*len = str->length();
	memcpy(rawStr, str->c_str(), *len);
}

}
