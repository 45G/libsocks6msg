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
#include <socks6msg.h>

using namespace std;

namespace S6M {

class Exception: exception
{
	enum S6M_Error error;
	
public:
	Exception(enum S6M_Error error)
		: error(error) {}

	//const char *what() const;
	
	S6M_Error getError() const
	{
		return error;
	}
};

class ByteBuffer
{
	uint8_t *buf;
	size_t used;
	size_t totalSize;
	
public:
	ByteBuffer(uint8_t *buf, size_t size)
		: buf(buf), used(0), totalSize(size) {}
	
	uint8_t *getBuf() const
	{
		return buf;
	}
	
	size_t getUsed() const
	{
		return used;
	}
	
	
	size_t getTotalSize() const
	{
		return totalSize;
	}
	
	template <typename T> void put(T *what, size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw Exception(S6M_ERR_BUFFER);
		
		memcpy(buf + used, what, req);
		used += req;
	}
	
	template <typename T> T *get(size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw Exception(S6M_ERR_BUFFER);
		
		T *ret = reinterpret_cast<T *>(buf + used);
		used += req;
		return ret;
		
	}
};

}

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

//TODO: get rid of this
static void Addr_Validate(const S6M_Addr *addr)
{
	ssize_t domPackedLen;
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
	case SOCKS6_ADDR_IPV6:
		return;
		
	case SOCKS6_ADDR_DOMAIN:
		domPackedLen = String_Packed_Size(addr->domain);
		if (domPackedLen == 1) /* empty string */
			throw Exception(S6M_ERR_INVALID);
		return;
	}
	
	throw Exception(S6M_ERR_BADADDR);
}

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
	(void)authReply; (void)err;
	return sizeof(SOCKS6Version) + sizeof(SOCKS6AuthReply);
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
		authReply->type = rawAuthReply->type;
		authReply->method = rawAuthReply->method;
		
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
		
		SOCKS6Options *rawOptHeader = bb.get<SOCKS6Options>();
		rawOptHeader->optionCount = 0;
		
		if (opReply->tfo)
		{
			rawOptHeader->optionCount++;
			
			SOCKS6SocketOption *rawTFOOption = bb.get<SOCKS6SocketOption>();
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
		
		if (opReply->mptcp)
		{
			rawOptHeader->optionCount++;
			
			SOCKS6SocketOption *rawMPTCPOption = bb.get<SOCKS6SocketOption>();
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
		if (opReply->mptcpSched.proxyServer != 0)
		{
			rawOptHeader->optionCount++;
			
			switch (opReply->mptcpSched.proxyServer)
			{
			case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
			case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
			case SOCKS6_MPTCP_SCHEDULER_RR:
				break;
				
			default:
				throw Exception(S6M_ERR_INVALID);
			}
			
			mpSchedOption = bb.get<SOCKS6MPTCPSchedulerOption>();
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
		if (opReply->mptcpSched.clientProxy != 0)
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
		
		if (opReply->idempotence.advertise)
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
	//TODO
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
		
		String_Pack(&bb, pwReq->username);
		String_Pack(&bb, pwReq->passwd);
		
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
		
		username = String_Parse(&bb);
		passwd = String_Parse(&bb);
		
		pwReq = new S6M_PasswdReq();
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
