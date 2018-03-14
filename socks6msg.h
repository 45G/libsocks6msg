/*-
 * Copyright (c) 2018 University Politehnica of Bucharest
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SOCKS6MSG_H
#define SOCKS6MSG_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <socks6.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

struct S6M_Request
{
	enum SOCKS6RequestCode reqCode;
	
	struct
	{
		enum SOCKS6AddressType type;
		struct in_addr ipv4;
		struct in6_addr ipv6;
		char *domain;
	} addr;
	
	uint16_t port;
	
	uint16_t initialDataLen;
	
	int tfo;
	
	struct
	{
		enum SOCKS6MPTCPScheduler clientProxy;
		enum SOCKS6MPTCPScheduler proxyServer;
	} mptcpSched;
	
	struct
	{
		int request;
		int spend;
		uint32_t token;
	} idempotence;
	
	struct
	{
		int use;
		uint32_t value;
	} salt;
	
	uint8_t *supportedMethods;
	
	struct
	{
		char *username;
		char *passwd;
	} userPasswdAuth;
};

struct S6M_AuthReply
{
	enum SOCKS6AuthReplyCode repCode;
	
	enum SOCKS6Method method;
};

struct S6M_OpReply
{
	struct
	{
		enum SOCKS6AddressType type;
		struct in_addr ipv4;
		struct in6_addr ipv6;
		char *domain;
	} addr;
	
	uint16_t port;
	
	int tfo;
	
	int mptcp;
	
	struct
	{
		enum SOCKS6MPTCPScheduler clientProxy;
		enum SOCKS6MPTCPScheduler proxyServer;
	} mptcpSched;
	
	struct
	{
		int advertise;
		uint32_t base;
		uint32_t windowSize;
	} idempotence;
	
	struct
	{
		int use;
		uint32_t value;
	} salt;
};

struct S6M_PasswdReq
{
	char *username;
	char *passwd;
};

struct S6M_PasswdReply
{
	int fail;
};
		
enum S6M_Error
{
	S6M_ERROR_SUCCESS     = 0,
	S6M_ERROR_INVALID     = -1,   /* some invalid field */
	S6M_ERROR_ALLOC       = -2,   /* malloc fail */
	S6M_ERROR_BUFFER      = -3,   /* reached end of buffer */
	S6M_ERROR_OTHERVER    = -4,   /* socks version other than 105 */
	S6M_ERROR_UNSUPPORTED = -100, /* unsupported/unimplemented stuff */
};

ssize_t S6M_Request_Pack    (const struct S6M_Request     *req,       char *buf, int size, enum S6M_Error *err);
ssize_t S6M_AuthReply_Pack  (const struct S6M_AuthReply   *authReply, char *buf, int size, enum S6M_Error *err);
ssize_t S6M_OpReply_Pack    (const struct S6M_OpReply     *opReply,   char *buf, int size, enum S6M_Error *err);
ssize_t S6M_PasswdReq_Pack  (const struct S6M_PasswdReq   *pwReq,     char *buf, int size, enum S6M_Error *err);
ssize_t S6M_PasswdReply_Pack(const struct S6M_PasswdReply *pwReply,   char *buf, int size, enum S6M_Error *err);

ssize_t S6M_Request_Packed_Size    (const struct S6M_Request     *req,       enum S6M_Error *err);
ssize_t S6M_AuthReply_Packed_Size  (const struct S6M_AuthReply   *authReply, enum S6M_Error *err);
ssize_t S6M_OpReply_Packed_Size    (const struct S6M_OpReply     *opReply,   enum S6M_Error *err);
ssize_t S6M_PasswdReq_Packed_Size  (const struct S6M_PasswdReq   *pwReq,     enum S6M_Error *err);
ssize_t S6M_PasswdReply_Packed_Size(const struct S6M_PasswdReply *pwReply,   enum S6M_Error *err);

struct S6M_Request     *S6M_Request_Parse    (char *buf, int size, enum S6M_Error *err);
struct S6M_AuthReply   *S6M_AuthReply_Parse  (char *buf, int size, enum S6M_Error *err);
struct S6M_OpReply     *S6M_OpReply_Parse    (char *buf, int size, enum S6M_Error *err);
struct S6M_PasswdReq   *S6M_PasswdReq_Parse  (char *buf, int size, enum S6M_Error *err);
struct S6M_PasswdReply *S6M_PasswdReply_Parse(char *buf, int size, enum S6M_Error *err);

void S6M_Request_Free    (struct S6M_Request     *req);
void S6M_AuthReply_Free  (struct S6M_AuthReply   *authReply);
void S6M_OpReply_Free    (struct S6M_OpReply     *opReply);
void S6M_PasswdReq_Free  (struct S6M_PasswdReq   *pwReq);
void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOCKS6MSG_H
