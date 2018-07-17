#ifndef SOCKS6MSG_H
#define SOCKS6MSG_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <unistd.h>
#include "socks6.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

struct S6M_Address
{
	enum SOCKS6AddressType type;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	char *domain;
};

#define S6M_ADDRESS_INVALID_TYPE 0

struct S6M_OptionSet
{
	int tfo;
	
	int mptcp;
	
	struct
	{
		enum SOCKS6MPTCPScheduler clientProxy;
		enum SOCKS6MPTCPScheduler proxyServer;
		
	} mptcpSched;
	
	struct
	{
		uint32_t request;
		
		int spend;
		uint32_t token;
		
		uint32_t windowBase;
		uint32_t windowSize;
		
		enum SOCKS6TokenExpenditureCode replyCode;
	} idempotence;
	
	enum SOCKS6Method *knownMethods;
	
	struct
	{
		char *username;
		char *passwd;
	} userPasswdAuth;
};

struct S6M_Request
{
	enum SOCKS6RequestCode code;
	
	struct S6M_Address addr;
	uint16_t port;
	
	uint16_t initialDataLen;
	
	struct S6M_OptionSet optionSet;
};

struct S6M_AuthReply
{
	enum SOCKS6AuthReplyCode code;
	
	enum SOCKS6Method method;
	
	struct S6M_OptionSet optionSet;
};

struct S6M_OpReply
{
	enum SOCKS6OperationReplyCode code;
	
	struct S6M_Address addr;
	uint16_t port;
	
	uint16_t initDataOff;
	
	struct S6M_OptionSet optionSet;
};

struct S6M_PasswdReq
{
	char *username;
	char *passwd;
};

struct S6M_PasswdReply
{
	int success;
};
		
enum S6M_Error
{
	S6M_ERR_SUCCESS     = 0,
	S6M_ERR_INVALID     = -1,   /* some invalid field */
	S6M_ERR_ALLOC       = -2,   /* malloc fail */
	S6M_ERR_BUFFER      = -3,   /* reached end of buffer */
	S6M_ERR_OTHERVER    = -4,   /* protocol version other than the one supported */
	S6M_ERR_UNSPEC      = -100, /* unspecified error */
};

const char *S6M_Error_msg(enum S6M_Error err);

ssize_t S6M_Request_pack    (const struct S6M_Request     *req,       uint8_t *buf, size_t size);
ssize_t S6M_AuthReply_pack  (const struct S6M_AuthReply   *authReply, uint8_t *buf, size_t size);
ssize_t S6M_OpReply_pack    (const struct S6M_OpReply     *opReply,   uint8_t *buf, size_t size);
ssize_t S6M_PasswdReq_pack  (const struct S6M_PasswdReq   *pwReq,     uint8_t *buf, size_t size);
ssize_t S6M_PasswdReply_pack(const struct S6M_PasswdReply *pwReply,   uint8_t *buf, size_t size);

ssize_t S6M_Request_packedSize    (const struct S6M_Request     *req);
ssize_t S6M_AuthReply_packedSize  (const struct S6M_AuthReply   *authReply);
ssize_t S6M_OpReply_packedSize    (const struct S6M_OpReply     *opReply);
ssize_t S6M_PasswdReq_packedSize  (const struct S6M_PasswdReq   *pwReq);
ssize_t S6M_PasswdReply_packedSize(const struct S6M_PasswdReply *pwReply);

ssize_t S6M_Request_parse    (uint8_t *buf, size_t size, struct S6M_Request     **preq);
ssize_t S6M_AuthReply_parse  (uint8_t *buf, size_t size, struct S6M_AuthReply   **pauthReply);
ssize_t S6M_OpReply_parse    (uint8_t *buf, size_t size, struct S6M_OpReply     **popReply);
ssize_t S6M_PasswdReq_parse  (uint8_t *buf, size_t size, struct S6M_PasswdReq   **ppwReq);
ssize_t S6M_PasswdReply_parse(uint8_t *buf, size_t size, struct S6M_PasswdReply **ppwReply);

void S6M_Request_free    (struct S6M_Request     *req);
void S6M_AuthReply_free  (struct S6M_AuthReply   *authReply);
void S6M_OpReply_free    (struct S6M_OpReply     *opReply);
void S6M_PasswdReq_free  (struct S6M_PasswdReq   *pwReq);
void S6M_PasswdReply_free(struct S6M_PasswdReply *pwReply);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6MSG_H
