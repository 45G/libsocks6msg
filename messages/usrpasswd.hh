#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include <string>
#include "bytebuffer.hh"
#include "string.hh"

namespace S6M
{

class UserPasswordBase
{
protected:
	static const uint8_t VERSION = 0x01;
};

class UserPasswordRequest: public UserPasswordBase
{
	String username;
	String password;
	
public:
	UserPasswordRequest(const std::shared_ptr<std::string> username, const std::shared_ptr<std::string> password)
		: username(username), password(password) {}
	
	UserPasswordRequest(const String &username, const String &password)
		: username(username), password(password) {}
	
	UserPasswordRequest(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb) const;
	
	size_t pack(uint8_t *buf, size_t bufSize) const;
	
	size_t packedSize() const
	{
		return 1 + username.packedSize() + password.packedSize();
	}
	
	const std::shared_ptr<std::string> getUsername() const
	{
		return username.getStr();
	}
	
	const std::shared_ptr<std::string> getPassword() const
	{
		return password.getStr();
	}
};

class UserPasswordReply: public UserPasswordBase
{
	bool success;
	
public:
	UserPasswordReply(bool success)
		: success(success) {}
	
	UserPasswordReply(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
	
	static size_t packedSize()
	{
		return 2;
	}
	
	bool isSuccessful()
	{
		return success;
	}
};

}

#endif // SOCKS6MSG_USRPASSWD_HH