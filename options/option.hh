#ifndef SOCKS6MSG_OPTION_HH
#define SOCKS6MSG_OPTION_HH

#include <set>
#include <vector>
#include <string>
#include "socks6.h"
#include "bytebuffer.hh"
#include "usrpasswd.hh"

namespace S6M
{

class OptionSet;

class Option
{
	SOCKS6OptionKind kind;
	
protected:
	virtual void fill(uint8_t *buf) const;
	
public:
	SOCKS6OptionKind getKind() const
	{
		return kind;
	}
	
	virtual size_t packedSize() const = 0;
	
	void pack(ByteBuffer *bb) const
	{
		uint8_t *buf = bb->get<uint8_t>(packedSize());
		
		fill(buf);
	}
	
	static void incementalParse(void *buf, size_t optionLen, OptionSet *optionSet);
	
	Option(SOCKS6OptionKind kind)
		: kind(kind) {}
	
	virtual ~Option();
};

}

#endif // SOCKS6MSG_OPTION_HH
