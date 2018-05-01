#include <iostream>
#include "socks6msg.h"
#include "socks6msg.hh"

using namespace std;
using namespace boost;
using namespace S6M;

void reqTest()
{
	Request req(SOCKS6_REQUEST_CONNECT, Address("gizoogle.com"), 80, OptionSet(), 1234);
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	req.pack(&bb);
	
	ByteBuffer bb2(buffer, 1000);
	Request req2(&bb2);
	
	cout << "req ok" << endl;
}

void authTest()
{
	
	AuthenticationReply arep(SOCKS6_AUTH_REPLY_SUCCESS, SOCKS6_METHOD_NOAUTH, OptionSet());
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	arep.pack(&bb);
	
	ByteBuffer bb2(buffer, 1000);
	AuthenticationReply arep2(&bb2);
	
	cout << "auth ok" << endl;
}

void opTest()
{
	
	OperationReply orep(SOCKS6_OPERATION_REPLY_SUCCESS, Address("gizoogle.com"), 80, 1234, OptionSet());
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	orep.pack(&bb);
	
	ByteBuffer bb2(buffer, 1000);
	OperationReply orep2(&bb2);
		
	cout << "op ok" << endl;
}

void upwTest()
{
	UserPasswordRequest upw("caca", "maca");
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	upw.pack(&bb);
	
	ByteBuffer bb2(buffer, 1000);
	UserPasswordRequest upw2(&bb2);
	
	cout << "upw ok" << endl;
}

void xmasTest()
{
	OptionSet ops;
	
	ops.setTFO();
	ops.setMPTCP();
	
	ops.setClientProxySched(SOCKS6_MPTCP_SCHEDULER_REDUNDANT);
	ops.setProxyServerSched(SOCKS6_MPTCP_SCHEDULER_RR);
	
	ops.requestTokenWindow();
	ops.spendToken(789);
	ops.advetiseTokenWindow(123, 456);
	ops.replyToExpenditure(SOCKS6_TOK_EXPEND_OUT_OF_WND);
	
	ops.advertiseMethod(SOCKS6_METHOD_GSSAPI);
	
	ops.attemptUserPasswdAuth("caca", "maca");
	
	OperationReply orep(SOCKS6_OPERATION_REPLY_SUCCESS, Address("gizoogle.com"), 80, 1234, ops);
	uint8_t buffer[1000];
	ByteBuffer bb(buffer, 1000);
	orep.pack(&bb);
	
	ByteBuffer bb2(buffer, 1000);
	OperationReply orep2(&bb2);
	
	cout << "xmas ok" << endl;
}

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
	
	reqTest();
	authTest();
	opTest();
	upwTest();
	xmasTest();
	
	return 0;
}
