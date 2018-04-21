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
#include "socks6msg_option.hh"

using namespace std;

using namespace S6M;


//TODO: move to base
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
		return 1 + stringPackedSize(addr->domain);
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
		stringPack(bb, addr->domain, true);
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
		addr.domain = stringParse(bb, true);
		break;
		
	default:
		throw Exception(S6M_ERR_BADADDR);
	}
	
	return addr;
}

/*
 * Options
 */ 
struct OptionSet
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
		
		bool reply;
		SOCKS6TokenExpenditureCode replyCode;
	} idempotence;
	
	set<SOCKS6Method> extraMethods;
	
	struct
	{
		string username;
		string passwd;
	} userPasswdAuth;
	
	list<Option *> opts;
	
//	Options()
//	{
//		tfo = false;
		
//		mptcp = false;
		
//		mptcpSched.clientProxy = (SOCKS6MPTCPScheduler)0;
//		mptcpSched.proxyServer = (SOCKS6MPTCPScheduler)0;
		
//		idempotence.request = false;
//		idempotence.spend = false;
//		idempotence.advertise = false;
//		idempotence.reply = false;
//	}
	
	OptionSet(const S6M_Request *req)
	{
		tfo = req->tfo;
		
		mptcp = false;
		
		mptcpSched.clientProxy = req->mptcpSched.clientProxy;
		mptcpSched.proxyServer = req->mptcpSched.proxyServer;
		
		idempotence.request = req->idempotence.request;
		idempotence.spend = req->idempotence.spend;
		idempotence.token = req->idempotence.token;
		idempotence.advertise = false;
		idempotence.reply = false;
		
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
		
		generate();
	}
	
	OptionSet(const S6M_AuthReply *authReply)
	{
		(void)authReply;
		
		tfo = false;
		
		mptcp = false;
		
		mptcpSched.clientProxy = (SOCKS6MPTCPScheduler)0;
		mptcpSched.proxyServer = (SOCKS6MPTCPScheduler)0;
		
		idempotence.request = false;
		idempotence.spend = false;
		idempotence.advertise = false;
		idempotence.reply = false;
		
		generate();
	}
	
	OptionSet(const S6M_OpReply *opReply)
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
		idempotence.reply = opReply->idempotence.reply;
		idempotence.replyCode = opReply->idempotence.replyCode;
		
		generate();
	}
	
	void generate()
	{
		if (tfo)
			opts.push_back(new TFOOption());
		if (mptcp)
			opts.push_back(new MPTCPOption());
		
		if (mptcpSched.clientProxy > 0)
		{
			if (mptcpSched.proxyServer == mptcpSched.clientProxy)
			{
				opts.push_back(new MPScehdOption(SOCKS6_SOCKOPT_LEG_BOTH, mptcpSched.clientProxy));
				goto both_sched_done;
			}
			else
			{
				opts.push_back(new MPScehdOption(SOCKS6_SOCKOPT_LEG_CLIENT_PROXY, mptcpSched.clientProxy));
			}
		}
		if (mptcpSched.proxyServer > 0)
			opts.push_back(new MPScehdOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, mptcpSched.proxyServer));
		
	both_sched_done:
		if (idempotence.request)
			opts.push_back(new TokenWindowRequestOption());
		if (idempotence.spend)
			opts.push_back(new TokenExpenditureRequestOption(idempotence.token));
		if (idempotence.advertise)
			opts.push_back(new TokenWindowAdvertOption(idempotence.base, idempotence.windowSize));
		if (idempotence.reply)
			opts.push_back(new TokenExpenditureReplyOption(idempotence.replyCode));
		
		if (!extraMethods.empty())
			opts.push_back(new AuthMethodOption(extraMethods));
		
		if (!userPasswdAuth.username.empty())
			opts.push_back(new UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd));
	}
};

static size_t Options_Packed_Size(const OptionSet *opts)
{
	size_t size = 0;
	
	size += sizeof(SOCKS6Options);
	
	BOOST_FOREACH(Option *opt, opts->opts)
	{
		size += opt->getLen();
	}
	
	return size;
}

static void Options_Pack(ByteBuffer *bb, const OptionSet *opts)
{
	SOCKS6Options *rawOptHeader = bb->get<SOCKS6Options>();
	rawOptHeader->optionCount = 0;
	
	BOOST_FOREACH(Option *opt, opts->opts)
	{
		rawOptHeader->optionCount++;
		opt->pack(bb);
	}
}

static OptionSet Options_Parse(ByteBuffer *bb)
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
		OptionSet options(authReply);
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
		
		OptionSet options(authReply);
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
		
		OptionSet options = Options_Parse(&bb);
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
		
		OptionSet opts(opReply);
		size += Options_Packed_Size(&opts);
		
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
		
		OptionSet options(opReply);
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
		
		OptionSet options = Options_Parse(&bb);
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
		ssize_t userPackedSize = stringPackedSize(pwReq->username);
		ssize_t passwdPackedSize = stringPackedSize(pwReq->passwd);
		
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
		
		stringPack(&bb, pwReq->username, true);
		stringPack(&bb, pwReq->passwd, true);
		
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
		
		username = stringParse(&bb, true);
		passwd = stringParse(&bb, true);
		
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
