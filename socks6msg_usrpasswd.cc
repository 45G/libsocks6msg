#include <boost/shared_ptr.hpp>
#include "socks6msg_usrpasswd.hh"

using namespace std;
using namespace boost;

namespace S6M
{

//TODO: create and use String class

std::string UserPasswordRequest::getUsername() const
{
	return username;
}

std::string UserPasswordRequest::getPassword() const
{
	return password;
}

UserPasswordRequest::UserPasswordRequest(const std::string &username, const std::string &password)
	: username(username), password(password)
{
	if (username.length() == 0 || password.length() == 0)
		throw Exception(S6M_ERR_INVALID);
	
	if (username.length() > 255 || password.length() > 255)
		throw Exception(S6M_ERR_INVALID);
	
	if (username.find_first_of('\0') != string::npos || password.find_first_of('\0') != string::npos)
		throw Exception(S6M_ERR_INVALID);
}

void UserPasswordRequest::pack(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	*ver = VERSION;
	
	stringPack(bb, username.c_str());
	stringPack(bb, password.c_str());
}

UserPasswordRequest *UserPasswordRequest::parse(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw Exception(S6M_ERR_OTHERVER);
	
	shared_ptr<char> cusr = shared_ptr<char>(stringParse(bb));
	shared_ptr<char> cpwd = shared_ptr<char>(stringParse(bb));
	
	return new UserPasswordRequest(string(cusr), string(cpwd));
}

void UserPasswordReply::pack(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	uint8_t *status = bb->get<uint8_t>();
	
	*ver = VERSION;
	*status = success ? 0x00 : 0x01;
}

UserPasswordReply *UserPasswordReply::parse(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw Exception(S6M_ERR_OTHERVER);
	
	uint8_t *status = bb->get<uint8_t>();
	
	return new UserPasswordReply(*status == 0x00);
}

}
