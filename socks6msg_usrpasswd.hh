#ifndef SOCKS6MSG_USRPASSWD_HH
#define SOCKS6MSG_USRPASSWD_HH

#include <string>
#include "socks6msg_base.hh"

namespace S6M
{

class UserPasswordBase
{
protected:
	static const uint8_t VERSION = 0x01;
};

class UserPasswordRequest: public UserPasswordBase
{
	std::string username;
	std::string password;
	
public:
	UserPasswordRequest(const std::string &username, const std::string &password);
	
	void pack(ByteBuffer *bb);
	
	size_t packedSize()
	{
		return 1 + stringPackedSize(username.c_str()) + stringPackedSize(password.c_str());
	}
	
	static UserPasswordRequest *parse(ByteBuffer *bb);
	
	std::string getUsername() const;
	
	std::string getPassword() const;
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
