#include <boost/shared_ptr.hpp>
#include "socks6msg_usrpasswd.hh"

using namespace std;
using namespace boost;

namespace S6M
{

void UserPasswordRequest::pack(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	*ver = VERSION;
	
	username.pack(bb);
	password.pack(bb);
}

UserPasswordRequest *UserPasswordRequest::parse(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw Exception(S6M_ERR_OTHERVER);
	
	shared_ptr<String> user = shared_ptr<String>(String::parse(bb));
	shared_ptr<String> pass = shared_ptr<String>(String::parse(bb));
	
	return new UserPasswordRequest(*user, *pass);
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
