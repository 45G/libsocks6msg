#ifndef SOCKS6MSG_STRING_HH
#define SOCKS6MSG_STRING_HH

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>
#include "../util/bytebuffer.hh"

namespace S6M
{

class String
{
	boost::shared_ptr<std::string> str;
	
public:
	//TODO: get rid of this constructor
	String() {}
	
	String(const boost::shared_ptr<std::string> str, bool nonEmpty = true);
	
	String(ByteBuffer *bb, bool nonEmpty = true);
	
	size_t packedSize() const
	{
		return 1 + str->length();
	}
	
	void pack(ByteBuffer *bb) const;
	
	const boost::shared_ptr<std::string> getStr() const
	{
		return str;
	}
};

}

#endif // SOCKS6MSG_STRING_HH
