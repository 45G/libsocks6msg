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
			throw Exception(S6M_ERROR_BUFFER);
		
		memcpy(buf + used, what, req);
		used += req;
	}
	
	template <typename T> T *get(size_t count = 1)
	{
		size_t req = sizeof(T) * count;
		
		if (req + used > totalSize)
			throw Exception(S6M_ERROR_BUFFER);
		
		T *ret = reinterpret_cast<T *>(buf + used);
		used += req;
		return ret;
		
	}
};

}

using namespace S6M;


/*
 * helpers
 */

#define S6M_DIE(errcode) \
{\
	*err = errcode; \
	return -1; \
}

#define S6M_PACKED_SIZE(type)  S6M_ ## type ## _Packed_Size 

#define S6M_SIZE_CHECK(type, ptr) \
{ \
	ssize_t psize = S6M_PACKED_SIZE(type)((ptr), err); \
	if (psize < 0) \
		return -1; \
	if (psize > (ssize_t)size) \
		S6M_DIE(S6M_ERROR_BUFFER); \
}

#define S6M_PROG_BEGIN() size_t S6M_crt = 0;

#define S6M_PROG(op) \
{ \
	ssize_t chunk = (op); \
	if (chunk < 0) \
		goto error; \
	S6M_crt += chunk; \
	size -= chunk; \
}

#define S6M_PROG_END() S6M_crt;

/*
 * pregenerated stuff
 */

static const SOCKS6SocketOption tfoOption = {
	.optionHead = {
		.kind = SOCKS6_OPTION_SOCKET,
		.len = sizeof(SOCKS6SocketOption),
	},
	.leg = SOCKS6_SOCKOPT_LEG_PROXY_SERVER,
	.level = SOCKS6_SOCKOPT_LEVEL_TCP,
	.code = SOCKS6_SOCKOPT_CODE_TFO,
};

static const SOCKS6SocketOption mptcpOption = {
	.optionHead = {
		.kind = SOCKS6_OPTION_SOCKET,
		.len = sizeof(SOCKS6SocketOption),
	},
	.leg = SOCKS6_SOCKOPT_LEG_PROXY_SERVER,
	.level = SOCKS6_SOCKOPT_LEVEL_TCP,
	.code = SOCKS6_SOCKOPT_CODE_TFO,
};

/*
 * raw
 */

template <typename T> static ssize_t S6M_Raw_Packed_Size(const T *item, enum S6M_Error *err)
{
	(void)item; (void)err;
	return sizeof(T);
}

template <typename T> static ssize_t S6M_Raw_Pack(const T *item, uint8_t *buf, size_t size, enum S6M_Error *err)
{
	S6M_SIZE_CHECK(Raw, item);
	*(reinterpret_cast<T *>(buf)) = *item;
	return sizeof(T);
}

template <typename T> static ssize_t S6M_Raw_Parse(uint8_t *buf, size_t size, T **pitem, enum S6M_Error *err)
{
	if (size < sizeof(T))
		S6M_DIE(S6M_ERROR_BUFFER);
	T *item = (T *)malloc(sizeof(T));
	*item = *(reinterpret_cast<const T *>(buf));
	
	*pitem = item;
	return sizeof(T);
}

static ssize_t String_Packed_Size(const char *str)
{
	if (!str)
		return 1;
	size_t len = strlen(str);
	if (len > 255)
		throw Exception(S6M_ERROR_INVALID);
	return 1 + len;
}

static void String_Pack(ByteBuffer *bb, char *str)
{
	size_t len = str ? strlen(str) : 0;
	if (len > 255)
		throw Exception(S6M_ERROR_INVALID);
	
	uint8_t *rawLen = bb->get<uint8_t>();
	*rawLen = (uint8_t)len;
	
	uint8_t *rawStr = bb->get<uint8_t>(len);
	memcpy(rawStr, str, len);
}

static char *String_Parse(ByteBuffer *bb)
{
	uint8_t *len = bb->get<uint8_t>();
	uint8_t *rawStr = bb->get<uint8_t>(*len);
	
	for (int i = 0; i < (int)(*len); i++)
	{
		//TODO: unlikely
		if (rawStr[i] == '\0')
			throw Exception(S6M_ERROR_INVALID);
	}
	
	char *str = new char[*len + 1];
	
	memcpy(str, rawStr, len);
	str[len] = '\0';
	
	return str;
}

/*
 * SGM_Addr_*
 */

int S6M_Addr_Validate(const struct S6M_Addr *addr, enum S6M_Error *err)
{
	ssize_t domPackedLen;
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
		return 0;
	case SOCKS6_ADDR_IPV6:
		return 0;
	case SOCKS6_ADDR_DOMAIN:
		domPackedLen = S6M_String_Packed_Size(addr->domain, err);
		if (domPackedLen == 1) /* empty string */
			break;
		return domPackedLen > 0 ? 1 : -1;
	}
	
	*err = S6M_ERROR_INVALID;
	return -1;
}

ssize_t S6M_Addr_Packed_Size(const struct S6M_Addr *addr, enum S6M_Error *err)
{
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
		return sizeof(addr->ipv4);
	case SOCKS6_ADDR_IPV6:
		return sizeof(addr->ipv6);
	case SOCKS6_ADDR_DOMAIN:
		return S6M_String_Packed_Size(addr->domain, err);
	}
	
	*err = S6M_ERROR_INVALID;
	return -1;
}

ssize_t S6M_Addr_Pack(const struct S6M_Addr *addr, uint8_t *buf, int size, enum S6M_Error *err)
{
	ssize_t domainPackLen;
	switch(addr->type)
	{
	case SOCKS6_ADDR_IPV4:
		if (S6M_Raw_Pack(&addr->ipv4, buf, size, err) < 0)
			return -1;
		return sizeof(addr->ipv4);
	case SOCKS6_ADDR_IPV6:
		if (S6M_Raw_Pack(&addr->ipv6, buf, size, err) < 0)
			return -1;
		return sizeof(addr->ipv6);
	case SOCKS6_ADDR_DOMAIN:
		domainPackLen = String_Pack(addr->domain, buf, size, err);
		if (domainPackLen < 0)
			return -1;
		if (domainPackLen == 1)
		{
			*err = S6M_ERROR_INVALID;
			return -1;
		}
		return domainPackLen;
	}
	
	*err = S6M_ERROR_INVALID;
	return -1;
}

/*
 * S6M_Request_*
 */
ssize_t S6M_Request_Packed_Size(const struct S6M_Request *req, enum S6M_Error *err) {}
ssize_t S6M_Request_Pack(const struct S6M_Request *req, uint8_t *buf, int size, enum S6M_Error *err) {}
ssize_t S6M_Request_Parse(uint8_t *buf, size_t size, S6M_Request **preq, enum S6M_Error *err) {}

void S6M_Request_Free(struct S6M_Request *req)
{
	free(req->addr.domain);
	free(req->supportedMethods);
	free(req->userPasswdAuth.username);
	free(req->userPasswdAuth.passwd);
	free(req);
}

/*
 * S6M_AuthReply_*
 */

static int S6M_AuthReply_Validate(const struct S6M_AuthReply *authReply, S6M_Error *err)
{
	switch (authReply->repCode)
	{
	case SOCKS6_AUTH_REPLY_SUCCESS:
	case SOCKS6_AUTH_REPLY_MORE:
		return 0;
	}
	
	*err = S6M_ERROR_INVALID;
	return -1;
}

ssize_t S6M_AuthReply_Packed_Size(const struct S6M_AuthReply *authReply, enum S6M_Error *err)
{
	(void)authReply; (void)err;
	return sizeof(SOCKS6Version) + sizeof(SOCKS6AuthReply);
}

ssize_t S6M_AuthReply_Pack(const struct S6M_AuthReply *authReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	if (S6M_AuthReply_Validate(authReply, err) < 0)
		return -1;
	
	SOCKS6Version ver = { SOCKS6_VERSION_MAJOR, SOCKS6_VERSION_MINOR };
	SOCKS6AuthReply rawAuthReply = { authReply->repCode, authReply->method };
	
	S6M_PROG_BEGIN();
	S6M_PROG(S6M_Raw_Pack(&ver, buf, size, err));
	S6M_PROG(S6M_Raw_Pack(&rawAuthReply, buf, size, err));
	return S6M_PROG_END();
	
error:
	return -1;
}

ssize_t S6M_AuthReply_Parse(uint8_t *buf, size_t size, S6M_AuthReply **pauthReply, enum S6M_Error *err)
{
	SOCKS6Version *ver = NULL;
	SOCKS6AuthReply *rawAuthReply = NULL;
	S6M_AuthReply *authReply = NULL;
	
	S6M_PROG_BEGIN();
	
	S6M_PROG(S6M_Raw_Parse(buf, size, &ver, err));
	if (ver->major != SOCKS6_VERSION_MAJOR || ver->minor != SOCKS6_VERSION_MINOR)
		goto error;
	free(ver);
	
	S6M_PROG(S6M_Raw_Parse(buf, size, &rawAuthReply, err));
	authReply = (S6M_AuthReply *)malloc(sizeof(S6M_AuthReply));
	authReply->repCode = (SOCKS6AuthReplyCode)rawAuthReply->type;
	authReply->method = (SOCKS6Method)rawAuthReply->method;
	if (!S6M_AuthReply_Validate(authReply, err))
		goto error;
	free(rawAuthReply);
	
	*pauthReply = authReply;
	return S6M_PROG_END();
	
error:
	free(ver);
	free(rawAuthReply);
	free(authReply);
	return -1;
}

void S6M_AuthReply_Free(struct S6M_AuthReply *authReply)
{
	free(authReply);
}

/*
 * S6M_OpReply_*
 */

ssize_t S6M_OpReply_Packed_Size(const struct S6M_OpReply *opReply, enum S6M_Error *err)
{
	size_t size = sizeof(SOCKS6OperationReply);
	
	ssize_t addrSize = S6M_Addr_Packed_Size(&opReply->addr, err);
	if (addrSize < 0)
		return -1;
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

static int S6M_OpReply_Validate(const struct S6M_OpReply *opReply, enum S6M_Error *err)
{
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
		goto error;
	}
	
	if (S6M_Addr_Validate(&opReply->addr, err) < 0)
		return -1;
	
	if (opReply->port == 0)
		goto error;
	
	switch (opReply->mptcpSched.clientProxy)
	{
	case 0:
	case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
	case SOCKS6_MPTCP_SCHEDULER_RR:
	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		break;
		
	default:
		goto error;
	}
	
	switch (opReply->mptcpSched.proxyServer)
	{
	case 0:
	case SOCKS6_MPTCP_SCHEDULER_DEFAULT:
	case SOCKS6_MPTCP_SCHEDULER_RR:
	case SOCKS6_MPTCP_SCHEDULER_REDUNDANT:
		break;
		
	default:
		goto error;
	}
	
	if (opReply->idempotence.advertise && opReply->idempotence.windowSize == 0)
		goto error;
	
	return 0;
	
error:
	*err = S6M_ERROR_INVALID;
	return -1;
}

ssize_t S6M_OpReply_Pack(const struct S6M_OpReply *opReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	if (S6M_OpReply_Validate(opReply, err) < 0)
		return -1;
	
	list<SOCKS6Option *> options;
	int optionCount = 0;
	
	S6M_PROG_BEGIN();
	
	SOCKS6OperationReply rawOpReply = {
		.code = opReply->code,
		.initialDataOffset = opReply->initDataOff,
		.bindPort = opReply->port,
		.addressType = opReply->addr.type,
	};
	S6M_PROG(S6M_Raw_Pack(&rawOpReply, buf, size, err));
	
	
	if (opReply->tfo)
		optionCount++;
	if (opReply->mptcp)
		optionCount++;
	if (opReply->mptcpSched.clientProxy > 0)
	{
		optionCount++;
		if (opReply->mptcpSched.proxyServer != 0 && opReply->mptcpSched.proxyServer != opReply->mptcpSched.clientProxy)
			optionCount++;
	}
	if (opReply->idempotence.advertise)
		optionCount++;
	
	SOCKS6Options opts = { .optionCount = optionCount };
	S6M_PROG(S6M_Raw_Pack(opts, buf, size, err));
	
	if (opReply->tfo)
		S6M_PROG(S6M_Raw_Pack(&tfoOption, buf, size, err));
	
	if (opReply->mptcp)
	{
		
		S6M_PROG(S6M_Raw_Pack(&mptcpOption, buf, size, err));
	}
	
	
error:
	BOOST_FOREACH(SOCKS6Option *op, options)
	{
		free(option);
	}
}

ssize_t S6M_OpReply_Parse(uint8_t *buf, size_t size, S6M_OpReply **popReply, enum S6M_Error *err) {}

void S6M_OpReply_Free(struct S6M_OpReply *opReply)
{
	free(opReply->addr.domain);
	free(opReply);
}

/*
 * S6M_PasswdReq_*
 */

ssize_t S6M_PasswdReq_Packed_Size(const struct S6M_PasswdReq *pwReq, enum S6M_Error *err)
{
	try
	{
		static const ssize_t verPackedSize = 1;
		ssize_t userPackedSize = tring_Packed_Size(pwReq->username);
		ssize_t passwdPackedSize = String_Packed_Size(pwReq->passwd);
		
		return verPackedSize + userPackedSize + passwdPackedSize;
	}
	catch (S6M::Exception ex)
	{
		*err = ex.getError();
	}
	catch (bad_alloc)
	{
		*err = S6M_ERROR_ALLOC;
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
		*err = S6M_ERROR_ALLOC;
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
			throw Exception(S6M_ERROR_INVALID);
		
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
		*err = S6M_ERROR_ALLOC;
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
			throw S6M::Exception(S6M_ERROR_INVALID);
		
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
		*err = S6M_ERROR_ALLOC;
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
			throw S6M::Exception(S6M_ERROR_INVALID);
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
		*err = S6M_ERROR_ALLOC;
	}
	
	return -1;
}

void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply)
{
	delete pwReply;
}
