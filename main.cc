#include <iostream>
#include "socks6msg.hh"

using namespace std;
using namespace boost;
using namespace S6M;

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
	
	Request req(SOCKS6_REQUEST_CONNECT, Address("gizoogle.com"), 80, OptionSet(), 0);
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	req.pack(&bb);
	try
	{
		ByteBuffer bb2(buffer, 1000);
		Request req2(&bb2);
	}
	catch (Exception ex)
	{
		cout << ex.getError() << endl;
	}
	
	return 0;
}
