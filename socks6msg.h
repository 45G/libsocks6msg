#ifndef SOCKS6MSG_H
#define SOCKS6MSG_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

struct SOCKS6Msg_Request
{
	enum SOCKS6RequestCode reqCode;
	struct
	{
		struct in_addr ipv4;
		struct in6_addr ipv6;
		char *domain;
		uint8_t prefIPVer;
	} addr;
	uint16_t port;
	
	struct
	{
		uint8_t *data;
		uint16_t len;
	} initialData;
	
	struct
	{
		int request;
		int spend;
		uint32_t token;
	} idempotence;
	
	struct
	{
		struct
		{
			int clientProxy;
			int proxyServer;
		} nodelay;
		
		struct
		{
			uint8_t clientProxy;
			uint8_t proxyServer;
		} tos;
		
		uint8_t *tcpopt;
		
		struct
		{
			enum SOCKS6MPSched clientProxy;
			enum SOCKS6MPSched proxyServer;
		} mpSched;
	} features;
	
	uint8_t *supportedMethods;
	
	struct
	{
		char *username;
		char *passwd;
	} userPasswdAuth;
};

enum SOCKS6Msg_Error
{
	SOCKS6MSG_OK,
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6MSG_H
