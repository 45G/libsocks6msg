#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include <string>
#include "socks6msg_base.hh"
#include "socks6msg_string.hh"

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
	UserPasswordRequest(const std::string &username, const std::string &password)
		: username(username), password(password) {}
	
	UserPasswordRequest(const String &username, const String &password)
		: username(username), password(password) {}
	
	void pack(ByteBuffer *bb) const;
	
	size_t packedSize() const
	{
		return 1 + username.packedSize() + password.packedSize();
	}
	
	static UserPasswordRequest *parse(ByteBuffer *bb);
	
	std::string getUsername() const
	{
		return username.getStr();
	}
	
	std::string getPassword() const
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
	
	void pack(ByteBuffer *bb);
	
	size_t packedSize()
	{
		return 2;
	}
	
	UserPasswordReply *parse(ByteBuffer *bb);
	
	bool isSuccessful()
	{
		return success;
	}
};

}

#endif // SOCKS6MSG_USRPASSWD_HH
