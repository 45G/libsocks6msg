#include "usrpasswd.hh"
#include "exceptions.hh"

using namespace std;

namespace S6M
{

void UserPasswordRequest::pack(ByteBuffer *bb) const
{
	uint8_t *ver = bb->get<uint8_t>();
	*ver = VERSION;
	
	username.pack(bb);
	password.pack(bb);
}

UserPasswordReply::UserPasswordReply(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw BadVersionException(*ver);
	
	uint8_t *status = bb->get<uint8_t>();
	
	success = *status == 0x00;
}

void UserPasswordReply::pack(ByteBuffer *bb) const
{
	uint8_t *ver = bb->get<uint8_t>();
	uint8_t *status = bb->get<uint8_t>();
	
	*ver    = VERSION;
	*status = success ? 0x00 : 0x01;
}

}
