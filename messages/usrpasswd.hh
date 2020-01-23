#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include "messagebase.hh"
#include "string.hh"

namespace S6M
{

class UserPasswordRequest: public MessageBase<0x01, uint8_t>
{
	String username;
	String password;
	
public:
	UserPasswordRequest(const std::pair<std::string_view, std::string_view> &creds)
		: username(creds.first), password(creds.second) {}
	
	UserPasswordRequest(ByteBuffer *bb)
		: MessageBase(bb), username(bb), password(bb) {}
	
	std::pair<std::string_view, std::string_view> getCredentials() const
	{
		return { username.getStr(), password.getStr() };
		
	}
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
	
	size_t packedSize() const
	{
		return 1 + username.packedSize() + password.packedSize();
	}
};

struct UserPasswordReply: public MessageBase<0x01, uint8_t>
{
	bool success;
	
	UserPasswordReply(bool success)
		: success(success) {}
	
	UserPasswordReply(ByteBuffer *bb)
		: MessageBase(bb)
	{
		uint8_t *status = bb->get<uint8_t>();
		
		success = *status == 0x00;
	}
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const
	{
		ByteBuffer bb(buf, bufSize);
		pack(&bb);
		return bb.getUsed();
	}
	
	static size_t packedSize()
	{
		return 2;
	}
};

}

#endif // SOCKS6MSG_USRPASSWD_HH
