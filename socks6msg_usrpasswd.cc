#include <boost/shared_ptr.hpp>
#include "socks6msg_usrpasswd.hh"

using namespace std;
using namespace boost;

namespace S6M
{

UserPasswordRequest::UserPasswordRequest(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw BadVersionException();
	
	username = String(bb);
	password = String(bb);
}

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
		throw BadVersionException();
	
	uint8_t *status = bb->get<uint8_t>();
	
	success = *status == 0x00;
}

void UserPasswordReply::pack(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	uint8_t *status = bb->get<uint8_t>();
	
	*ver = VERSION;
	*status = success ? 0x00 : 0x01;
}

}
