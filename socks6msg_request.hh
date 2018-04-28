#ifndef SOCKS6MSG_REQUEST_HH
#define SOCKS6MSG_REQUEST_HH

#include "socks6msg_base.hh"
#include "socks6msg_address.hh"
#include "socks6msg_optionset.hh"

namespace S6M
{

class Request
{
	SOCKS6RequestCode commandCode;
	
	Address addr;
	uint16_t port;
	
	OptionSet optionSet;
	
	uint16_t initialDataLen;
	
public:
	Request(SOCKS6RequestCode commandCode, Address addr, uint16_t port, const OptionSet &optionSet, uint16_t initialDataLen);
	
	Request *parse(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
	
	size_t packedSize();
};

}

#endif // SOCKS6MSG_REQUEST_HH
