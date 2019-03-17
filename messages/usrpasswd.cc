#include "usrpasswd.hh"
#include "exception.hh"

using namespace std;

namespace S6M
{

UserPasswordRequest::UserPasswordRequest(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw BadVersionException(*ver);
	
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

size_t UserPasswordRequest::pack(uint8_t *buf, size_t bufSize) const
{
	ByteBuffer bb(buf, bufSize);
	pack(&bb);
	return bb.getUsed();
}

UserPasswordReply::UserPasswordReply(ByteBuffer *bb)
{
	uint8_t *ver = bb->get<uint8_t>();
	if (*ver != VERSION)
		throw BadVersionException(*ver);
	
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
