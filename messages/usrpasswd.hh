#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include <optional>
#include "bytebuffer.hh"
#include "string.hh"

namespace S6M
{

class UserPasswordBase
{
protected:
	static constexpr uint8_t VERSION = 0x01;
};

class UserPasswordRequest: public UserPasswordBase
{
	std::optional<String> username;
	std::optional<String> password;
	
public:
	UserPasswordRequest(const std::pair<std::string_view, std::string_view> &creds)
		: username(creds.first), password(creds.second) {}
	
	UserPasswordRequest(ByteBuffer *bb);
	
	std::pair<std::string_view, std::string_view> getCredentials() const
	{
		if (!username)
			return {};
		return { username->getStr(), password->getStr() };
		
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
		return 1 + username->packedSize() + password->packedSize();
	}
};

struct UserPasswordReply: public UserPasswordBase
{
	bool success;
	
	UserPasswordReply(bool success)
		: success(success) {}
	
	UserPasswordReply(ByteBuffer *bb);
	
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
