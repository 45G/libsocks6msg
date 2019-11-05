#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include <string>
#include <optional>
#include "bytebuffer.hh"
#include "string.hh"

namespace S6M
{

class UserPasswordBase
{
protected:
	static const uint8_t VERSION = 0x01;
};

struct UserPasswordRequest: public UserPasswordBase
{
	std::optional<String> username;
	std::optional<String> password;
	
	UserPasswordRequest(const std::string &username, const std::string &password)
		: username(username), password(password) {}
	
	UserPasswordRequest(const String &username, const String &password)
		: username(username), password(password) {}
	
	UserPasswordRequest(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
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
	
	void pack(ByteBuffer *bb);
	
	static size_t packedSize()
	{
		return 2;
	}
};

}

#endif // SOCKS6MSG_USRPASSWD_HH
