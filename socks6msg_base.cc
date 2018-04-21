#include <string.h>
#include "socks6msg_base.hh"

namespace S6M
{

size_t stringPackedSize(const char *str)
{
	if (!str)
		return 1;
	size_t len = strlen(str);
	if (len > 255)
		throw Exception(S6M_ERR_INVALID);
	return 1 + len;
}

void stringPack(ByteBuffer *bb, const char *str, bool nonEmpty)
{
	size_t len;
	if (str == NULL)
		len = 0;
	else
		len = strlen(str);
	if (len > 255)
		throw Exception(S6M_ERR_INVALID);
	if (nonEmpty && len == 0)
		throw Exception(S6M_ERR_INVALID);
	
	uint8_t *rawLen = bb->get<uint8_t>();
	*rawLen = (uint8_t)len;
	
	uint8_t *rawStr = bb->get<uint8_t>(len);
	memcpy(rawStr, str, len);
}

char *stringParse(ByteBuffer *bb, bool nonEmpty)
{
	uint8_t *len = bb->get<uint8_t>();
	if (*len == 0 && nonEmpty)
		throw Exception(S6M_ERR_INVALID);
	
	uint8_t *rawStr = bb->get<uint8_t>(*len);
	
	for (int i = 0; i < (int)(*len); i++)
	{
		//TODO: unlikely
		if (rawStr[i] == '\0')
			throw Exception(S6M_ERR_INVALID);
	}
	
	char *str = new char[*len + 1];
	
	memcpy(str, rawStr, *len);
	str[*len] = '\0';
	
	return str;
}

}
