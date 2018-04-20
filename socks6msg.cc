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

#include <stdlib.h>
#include <string.h>
#include <list>
#include <boost/foreach.hpp>
#include <set>
#include "socks6msg.h"
#include "socks6msg_base.hh"

using namespace std;

using namespace S6M;


/*
 * raw
 */

static ssize_t String_Packed_Size(const char *str)
{
	if (!str)
		return 1;
	size_t len = strlen(str);
	if (len > 255)
		throw Exception(S6M_ERR_INVALID);
	return 1 + len;
}

static void String_Pack(ByteBuffer *bb, char *str, bool nonEmpty = false)
{
	size_t len;
	if (str == NULL)
		len = 0;
	else
		len = strlen(str);
	if (len > 255)
		throw Exception(S6M_ERR_INVALID);
	if (nonEmpty && len == 0)
		throw Exception(S6M_ERR_INVALID);
	
	uint8_t *rawLen = bb->get<uint8_t>();
	*rawLen = (uint8_t)len;
	
	uint8_t *rawStr = bb->get<uint8_t>(len);
	memcpy(rawStr, str, len);
}

static char *String_Parse(ByteBuffer *bb, bool nonEmpty = false)
{
	uint8_t *len = bb->get<uint8_t>();
	if (*len == 0 && nonEmpty)
		throw Exception(S6M_ERR_INVALID);
	
	uint8_t *rawStr = bb->get<uint8_t>(*len);
	
	for (int i = 0; i < (int)(*len); i++)
	{
		//TODO: unlikely
		if (rawStr[i] == '\0')
			throw Exception(S6M_ERR_INVALID);
	}
	
	char *str = new char[*len + 1];
	
	memcpy(str, rawStr, *len);
	str[*len] = '\0';
	
	return str;
}

/*
 * SGM_Addr_*
 */
static ssize_t Addr_Packed_Size(const S6M_Addr *addr)
{
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
		return 1 + sizeof(addr->ipv4);
	case SOCKS6_ADDR_IPV6:
		return 1 + sizeof(addr->ipv6);
	case SOCKS6_ADDR_DOMAIN:
		return 1 + String_Packed_Size(addr->domain);
	}
	
	throw Exception(S6M_ERR_INVALID);
}

static void Addr_Pack(ByteBuffer *bb, const S6M_Addr *addr)
{
	uint8_t rawType = (uint8_t)addr->type;
	bb->put(&rawType);
	
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
		bb->put(&addr->ipv4);
		return;
		
	case SOCKS6_ADDR_IPV6:
		bb->put(&addr->ipv6);
		return;
		
	case SOCKS6_ADDR_DOMAIN:
		String_Pack(bb, addr->domain, true);
		return;
		
//	default:
//		throw Exception(S6M_ERR_BADADDR);
	}
	
	throw Exception(S6M_ERR_INVALID);
}

static S6M_Addr Addr_Parse(ByteBuffer *bb)
{
	uint8_t *type = bb->get<uint8_t>();
	S6M_Addr addr;
	addr.type = (SOCKS6AddressType)(*type);
	
	
	switch(addr.type)
	{
	case SOCKS6_ADDR_IPV4:
		addr.ipv4 = *(bb->get<in_addr>());
		break;
		
	case SOCKS6_ADDR_IPV6:
		addr.ipv6 = *(bb->get<in6_addr>());
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		addr.domain = String_Parse(bb, true);
		break;
		
	default:
		throw Exception(S6M_ERR_BADADDR);
	}
	
	return addr;
}

/*
 * Options
 */ 
struct Options
{
	bool tfo;
	
	bool mptcp;
	
	struct
	{
		SOCKS6MPTCPScheduler clientProxy;
		SOCKS6MPTCPScheduler proxyServer;
	} mptcpSched;
	
	struct
	{
		bool request;
		bool spend;
		uint32_t token;
		
		bool advertise;
		uint32_t base;
		uint32_t windowSize;
	} idempotence;
	
	set<SOCKS6Method> extraMethods;
	
	struct
	{
		string username;
		string passwd;
	} userPasswdAuth;
	
	Options()
	{
		tfo = false;
		
		mptcp = false;
		
		mptcpSched.clientProxy = (SOCKS6MPTCPScheduler)0;
		mptcpSched.proxyServer = (SOCKS6MPTCPScheduler)0;
		
		idempotence.request = false;
		idempotence.spend = false;
		idempotence.advertise = false;
	}
	
	Options(S6M_Request *req)
	{
		tfo = req->tfo;
		
		mptcp = false;
		
		mptcpSched.clientProxy = req->mptcpSched.clientProxy;
		mptcpSched.proxyServer = req->mptcpSched.proxyServer;
		
		idempotence.request = req->idempotence.request;
		idempotence.spend = req->idempotence.spend;
		idempotence.token = req->idempotence.token;
		idempotence.advertise = false;
		
		if (req->userPasswdAuth.username)
		{	
			userPasswdAuth.username = string(req->userPasswdAuth.username);
			userPasswdAuth.passwd = string(req->userPasswdAuth.passwd);
		}
		
		bool doUserPasswdAuth = userPasswdAuth.username.length() > 0;
		
		if (req->supportedMethods == NULL)
			return;
		for (int i = 0; req->supportedMethods[i] != SOCKS6_METHOD_NOAUTH; i++)
		{
			SOCKS6Method method = (SOCKS6Method)req->supportedMethods[i];
			if (method == SOCKS6_METHOD_UNACCEPTABLE)
				throw Exception(S6M_ERR_INVALID);
			if (method == SOCKS6_METHOD_USRPASSWD && doUserPasswdAuth)
				continue;
			extraMethods.insert(method);
		}
	}
	
	Options(S6M_AuthReply *authReply)
	{
		(void)authReply;
		
		tfo = false;
		
		mptcp = false;
		
		mptcpSched.clientProxy = (SOCKS6MPTCPScheduler)0;
		mptcpSched.proxyServer = (SOCKS6MPTCPScheduler)0;
		
		idempotence.request = false;
		idempotence.spend = false;
		idempotence.advertise = false;
	}
	
	Options(S6M_OpReply *opReply)
	{
		tfo = opReply->tfo;
		
		mptcp = opReply->mptcp;
		
		mptcpSched.clientProxy = opReply->mptcpSched.clientProxy;
		mptcpSched.proxyServer = opReply->mptcpSched.proxyServer;
		
		idempotence.request = false;
		idempotence.spend = false;
		idempotence.advertise = opReply->idempotence.advertise;
		idempotence.base = opReply->idempotence.base;
		idempotence.windowSize = opReply->idempotence.windowSize;
	}
};

static void Options_Packed_Size(const Options *opts)
{
	//TODO
	size += sizeof(SOCKS6Options);
	if (opReply->tfo)
		size += sizeof(SOCKS6SocketOption);
	if (opReply->mptcp)
		size += sizeof(SOCKS6SocketOption);
	if (opReply->mptcpSched.clientProxy > 0)
	{
		size += sizeof(SOCKS6MPTCPSchedulerOption);
		if (opReply->mptcpSched.proxyServer != 0 && opReply->mptcpSched.proxyServer != opReply->mptcpSched.clientProxy)
			size += sizeof(SOCKS6MPTCPSchedulerOption);
	}
	
	if (opReply->idempotence.advertise)
		size += sizeof(SOCKS6WindowAdvertOption);
}

static void Options_Pack(ByteBuffer *bb, const Options *opts)
{
	SOCKS6Options *rawOptHeader = bb->get<SOCKS6Options>();
	rawOptHeader->optionCount = 0;
	
	if (opts->tfo)
	{
		rawOptHeader->optionCount++;
		
		SOCKS6SocketOption *rawTFOOption = bb->get<SOCKS6SocketOption>();
		*rawTFOOption = {
			.optionHead = {
				.kind = SOCKS6_OPTION_SOCKET,
				.len = sizeof(SOCKS6SocketOption),
			},
			.level = SOCKS6_SOCKOPT_LEVEL_TCP,
			.leg = SOCKS6_SOCKOPT_LEG_PROXY_SERVER,
			.code = SOCKS6_SOCKOPT_CODE_TFO,
		};
	}
	
	if (opts->mptcp)
	{
		rawOptHeader->optionCount++;
		
		SOCKS6SocketOption *rawMPTCPOption = bb->get<SOCKS6SocketOption>();
		*rawMPTCPOption = {
			.optionHead = {
				.kind = SOCKS6_OPTION_SOCKET,
				.len = sizeof(SOCKS6SocketOption),
			},
			.level = SOCKS6_SOCKOPT_LEVEL_TCP,
			.leg = SOCKS6_SOCKOPT_LEG_PROXY_SERVER,
			.code = SOCKS6_SOCKOPT_CODE_MPTCP,
		};
	}
	
	SOCKS6MPTCPSchedulerOption *mpSchedOption = NULL;
	if (opts->mptcpSched.proxyServer != 0)
	{
		rawOptHeader->optionCount++;
		
		switch (opts->mptcpSched.proxyServer)
		{
		case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
		case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		case SOCKS6_MPTCP_SCHEDULER_RR:
			break;
			
		default:
			throw Exception(S6M_ERR_INVALID);
		}
		
		mpSchedOption = bb->get<SOCKS6MPTCPSchedulerOption>();
		*mpSchedOption = {
			.socketOptionHead = {
				.optionHead = {
					.kind = SOCKS6_OPTION_SOCKET,
					.len = sizeof(SOCKS6SocketOption),
				},
				.level = SOCKS6_SOCKOPT_LEVEL_TCP,
				.leg = SOCKS6_SOCKOPT_LEG_PROXY_SERVER,
				.code = SOCKS6_SOCKOPT_CODE_MP_SCHED,
			},
			.scheduler = opReply->mptcpSched.proxyServer,
		};
	}
	if (opts->mptcpSched.clientProxy != 0)
	{
		switch (opReply->mptcpSched.clientProxy)
		{
		case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
		case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		case SOCKS6_MPTCP_SCHEDULER_RR:
			break;
			
		default:
			throw Exception(S6M_ERR_INVALID);
		}
		
		if (mpSchedOption != NULL && opReply->mptcpSched.proxyServer == opReply->mptcpSched.clientProxy)
			mpSchedOption->socketOptionHead.leg = SOCKS6_SOCKOPT_LEG_BOTH;
		else
		{
			rawOptHeader->optionCount++;
			
			mpSchedOption = bb.get<SOCKS6MPTCPSchedulerOption>();
			*mpSchedOption = {
				.socketOptionHead = {
					.optionHead = {
						.kind = SOCKS6_OPTION_SOCKET,
						.len = sizeof(SOCKS6SocketOption),
					},
					.level = SOCKS6_SOCKOPT_LEVEL_TCP,
					.leg = SOCKS6_SOCKOPT_LEG_CLIENT_PROXY,
					.code = SOCKS6_SOCKOPT_CODE_MP_SCHED,
				},
				.scheduler = opReply->mptcpSched.proxyServer,
			};
		}
	}
	
	if (opts->idempotence.request)
	{
		//TODO
	}
	
	if (opts->idempotence.spend)
	{
		//TODO
	}
	
	if (opts->idempotence.advertise)
	{
		rawOptHeader->optionCount++;
		
		if (opReply->idempotence.windowSize == 0 || opReply->idempotence.windowSize >= (1UL << 31))
			throw Exception(S6M_ERR_INVALID);
		
		SOCKS6WindowAdvertOption *winAdvert = bb.get<SOCKS6WindowAdvertOption>();
		*winAdvert = {
			.idempotenceOptionHead = {
				.optionHead = {
					.kind = SOCKS6_OPTION_IDEMPOTENCE,
					.len = sizeof(SOCKS6WindowAdvertOption),
				},
				.type = SOCKS6_IDEMPOTENCE_WND_ADVERT,
			},
			.windowBase = opReply->idempotence.base,
			.windowSize = opReply->idempotence.windowSize,
		};
	}
	
	if (!opts->extraMethods.empty())
}

static Options Options_Parse(ByteBuffer *bb)
{
	//TODO
}


/*
 * S6M_Request_*
 */
ssize_t S6M_Request_Packed_Size(const struct S6M_Request *req, enum S6M_Error *err)
{
	//TODO
}

ssize_t S6M_Request_Pack(const struct S6M_Request *req, uint8_t *buf, int size, enum S6M_Error *err)
{
	//TODO
}

ssize_t S6M_Request_Parse(uint8_t *buf, size_t size, S6M_Request **preq, enum S6M_Error *err)
{
	//TODO
}

void S6M_Request_Free(struct S6M_Request *req)
{
	delete req->addr.domain;
	delete req->supportedMethods;
	delete req->userPasswdAuth.username;
	delete req->userPasswdAuth.passwd;
	delete req;
}

/*
 * S6M_AuthReply_*
 */

ssize_t S6M_AuthReply_Packed_Size(const struct S6M_AuthReply *authReply, enum S6M_Error *err)
{
	try
	{
		Options options(authReply);
		return sizeof(SOCKS6Version) + sizeof(SOCKS6AuthReply) + Options_Packed_Size(&options);
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_AuthReply_Pack(const struct S6M_AuthReply *authReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		if (authReply->type != SOCKS6_AUTH_REPLY_SUCCESS && authReply->type != SOCKS6_AUTH_REPLY_MORE)
			throw Exception(S6M_ERR_INVALID);
		
		SOCKS6Version *ver = bb.get<SOCKS6Version>();
		*ver = { 
			.major = SOCKS6_VERSION_MAJOR,
			.minor = SOCKS6_VERSION_MINOR,
		};
		
		SOCKS6AuthReply *rawAuthReply = bb.get<SOCKS6AuthReply>();
		*rawAuthReply =
		{
			.type = authReply->type,
			.method = authReply->method
		};
		
		Options options;
		Options_Pack(&bb, &options);
		
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_AuthReply_Parse(uint8_t *buf, size_t size, S6M_AuthReply **pauthReply, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		SOCKS6Version *ver = bb.get<SOCKS6Version>();
		if (ver->major != SOCKS6_VERSION_MAJOR || ver->minor != SOCKS6_VERSION_MINOR)
			throw Exception(S6M_ERR_OTHERVER);
		
		SOCKS6AuthReply *rawAuthReply = bb.get<SOCKS6AuthReply>();
		if (rawAuthReply->type != SOCKS6_AUTH_REPLY_SUCCESS && rawAuthReply->type != SOCKS6_AUTH_REPLY_MORE)
			throw Exception(S6M_ERR_INVALID);
		
		S6M_AuthReply *authReply = new S6M_AuthReply();
		memset(authReply, 0, sizeof(S6M_AuthReply));
		authReply->type = (SOCKS6AuthReplyCode)rawAuthReply->type;
		authReply->method = (SOCKS6Method)rawAuthReply->method;
		
		Options options = Options_Parse(&bb);
		(void)options; //no usable options in spec
		
		*pauthReply = authReply;
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

void S6M_AuthReply_Free(struct S6M_AuthReply *authReply)
{
	delete authReply;
}

/*
 * S6M_OpReply_*
 */

ssize_t S6M_OpReply_Packed_Size(const struct S6M_OpReply *opReply, enum S6M_Error *err)
{
	try
	{
		size_t size = sizeof(SOCKS6OperationReply);
		
		ssize_t addrSize = Addr_Packed_Size(&opReply->addr);
		size += addrSize;
		
		//TODO
		
		return size;
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_OpReply_Pack(const struct S6M_OpReply *opReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		switch (opReply->code)
		{
		case SOCKS6_OPERATION_REPLY_SUCCESS:
		case SOCKS6_OPERATION_REPLY_FAILURE:
		case SOCKS6_OPERATION_REPLY_NOT_ALLOWED:
		case SOCKS6_OPERATION_REPLY_NET_UNREACH:
		case SOCKS6_OPERATION_REPLY_HOST_UNREACH:
		case SOCKS6_OPERATION_REPLY_REFUSED:
		case SOCKS6_OPERATION_REPLY_TTL_EXPIRED:
		case SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED:
		case SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED:
			break;
			
		default:
			throw Exception(S6M_ERR_INVALID);
		}
		
		if (opReply->port == 0)
			throw Exception(S6M_ERR_INVALID);
		
		SOCKS6OperationReply *rawOpReply = bb.get<SOCKS6OperationReply>();
		*rawOpReply =
		{
			.code = opReply->code,
			.initialDataOffset = htons(opReply->initDataOff),
			.bindPort = htons(opReply->port),
		};
		
		Addr_Pack(&bb, &opReply->addr);
		
		Options options(opReply);
		Options_Pack(&bb, &options);
		
		return bb.getUsed();
		
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_OpReply_Parse(uint8_t *buf, size_t size, S6M_OpReply **popReply, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		SOCKS6OperationReply *rawOpReply = bb.get<SOCKS6OperationReply>();
		
		switch (rawOpReply->code)
		{
		case SOCKS6_OPERATION_REPLY_SUCCESS:
		case SOCKS6_OPERATION_REPLY_FAILURE:
		case SOCKS6_OPERATION_REPLY_NOT_ALLOWED:
		case SOCKS6_OPERATION_REPLY_NET_UNREACH:
		case SOCKS6_OPERATION_REPLY_HOST_UNREACH:
		case SOCKS6_OPERATION_REPLY_REFUSED:
		case SOCKS6_OPERATION_REPLY_TTL_EXPIRED:
		case SOCKS6_OPERATION_REPLY_CMD_NOT_SUPPORTED:
		case SOCKS6_OPERATION_REPLY_ADDR_NOT_SUPPORTED:
			break;
			
		default:
			throw Exception(S6M_ERR_INVALID);
		}
		
		if (rawOpReply->bindPort == 0)
			throw Exception(S6M_ERR_INVALID);
		
		Options options = Options_Parse(&bb);
		//TODO
		
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

void S6M_OpReply_Free(struct S6M_OpReply *opReply)
{
	delete opReply->addr.domain;
	delete opReply;
}

/*
 * S6M_PasswdReq_*
 */

ssize_t S6M_PasswdReq_Packed_Size(const struct S6M_PasswdReq *pwReq, enum S6M_Error *err)
{
	try
	{
		static const ssize_t verPackedSize = 1;
		ssize_t userPackedSize = String_Packed_Size(pwReq->username);
		ssize_t passwdPackedSize = String_Packed_Size(pwReq->passwd);
		
		return verPackedSize + userPackedSize + passwdPackedSize;
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_PasswdReq_Pack(const struct S6M_PasswdReq *pwReq, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		uint8_t *ver = bb.get<uint8_t>();
		*ver = SOCKS6_PWAUTH_VERSION;
		
		String_Pack(&bb, pwReq->username, true);
		String_Pack(&bb, pwReq->passwd, true);
		
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_PasswdReq_Parse(uint8_t *buf, size_t size, struct S6M_PasswdReq **ppwReq, enum S6M_Error *err)
{
	char *username = NULL;
	char *passwd = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		uint8_t *ver = bb.get<uint8_t>();
		if (*ver != SOCKS6_PWAUTH_VERSION)
			throw Exception(S6M_ERR_INVALID);
		
		username = String_Parse(&bb, true);
		passwd = String_Parse(&bb, true);
		
		S6M_PasswdReq *pwReq = new S6M_PasswdReq();
		memset(pwReq, 0, sizeof(S6M_PasswdReq));
		pwReq->username = username;
		pwReq->passwd = passwd;
		
		*ppwReq = pwReq;
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	delete username;
	delete passwd;
	return -1;
}

void S6M_PasswdReq_Free(struct S6M_PasswdReq *pwReq)
{
	delete pwReq->username;
	delete pwReq->passwd;
	delete pwReq;
}

/*
 * S6M_PasswdReply_*
 */

ssize_t S6M_PasswdReply_Packed_Size(const struct S6M_PasswdReply *pwReply, enum S6M_Error *err)
{
	(void) pwReply; (void)err;
	return 2;
}

ssize_t S6M_PasswdReply_Pack(const struct S6M_PasswdReply *pwReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		S6M::ByteBuffer bb(buf, size);
		
		if (pwReply->fail != 0 && pwReply->fail != 1)
			throw S6M::Exception(S6M_ERR_INVALID);
		
		uint8_t ver = 0x01;
		uint8_t fail = pwReply->fail;
		
		bb.put(&ver);
		bb.put(&fail);
		
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

ssize_t S6M_PasswdReply_Parse(uint8_t *buf, size_t size, S6M_PasswdReply **ppwReply, enum S6M_Error *err)
{
	try
	{
		S6M::ByteBuffer bb(buf, size);
		
		uint8_t *ver = bb.get<uint8_t>();
		uint8_t *fail = bb.get<uint8_t>();
		
		if (*ver != 0x01 ||
			(*fail != 0 && *fail != 1))
		{
			throw S6M::Exception(S6M_ERR_INVALID);
		}
		
		S6M_PasswdReply *pwReply = new S6M_PasswdReply();
		memset(pwReply, 0, sizeof(S6M_PasswdReply));
		pwReply->fail = *fail;
		*ppwReply = pwReply;
		
		return bb.getUsed();
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERR_ALLOC;
	}
	
	return -1;
}

void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply)
{
	delete pwReply;
}
