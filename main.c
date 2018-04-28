#include "socks6msg.h"

int main()
{
#if 0
	struct S6M_Request req = {
		.reqCode = SOCKS6_REQUEST_CONNECT,
		.addr = {
			.type = SOCKS6_ADDR_DOMAIN,
			.domain = "yahoo.com",
		},
		.port = 80,
	};
	
	uint8_t buf[1000];
	enum S6M_Error err;
	
	ssize_t size = S6M_Request_Pack(&req, buf, 1000, &err);
#endif
	return 0;
}
