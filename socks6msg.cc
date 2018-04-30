#include <stdlib.h>
#include <string.h>
#include <list>
#include <set>
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include "socks6msg.h"
#include "socks6msg.hh"

using namespace std;
using namespace boost;
using namespace S6M;

#define S6M_CATCH(err) \
	catch (InvalidFieldException) \
	{ \
		*(err) = S6M_ERR_INVALID; \
	} \
	catch (EndOfBufferException) \
	{ \
		*(err) = S6M_ERR_BUFFER; \
	} \
	catch (BadVersionException) \
	{ \
		*(err) = S6M_ERR_OTHERVER; \
	} \
	catch (bad_alloc) \
	{ \
		*(err) = S6M_ERR_ALLOC; \
	}

/*
 * S6m_Addr
 */

static void S6M_Addr_Cleanup(struct S6M_Addr *addr)
{
	delete addr->domain;
}

#if 0
/*
 * S6m_OptionSet
 */

static ssize_t S6M_OptionSet_Packed_Size(S6M_OptionSet *optionSet)
{
	//TODO
}

static void S6M_OptionSet_Cleanup(struct S6M_OptionSet *optionSet)
{
	delete optionSet->knownMethods;
	delete optionSet->userPasswdAuth.username;
	delete optionSet->userPasswdAuth.passwd;
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
	S6M_Addr_Cleanup(&req->addr);
	S6M_OptionSet_Cleanup(&req->optionSet);
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
		};Exception(S6M_ERR_OTHERVER)
		
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
		
		OptionSet options OptionSet::parse(&bb);
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
		
		OptionSet options = OptionSet::parse(&bb);
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
#endif

void S6M_OpReply_Free(struct S6M_OpReply *opReply)
{
	S6M_Addr_Cleanup(&opReply->addr);
	delete opReply;
}

/*
 * S6M_PasswdReq_*
 */

ssize_t S6M_PasswdReq_Packed_Size(const struct S6M_PasswdReq *pwReq, enum S6M_Error *err)
{
	try
	{
		UserPasswordRequest req(string(pwReq->username), string(pwReq->passwd));
		
		return req.packedSize();
	}
	S6M_CATCH(err)
	
	return -1;
}

ssize_t S6M_PasswdReq_Pack(const struct S6M_PasswdReq *pwReq, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		UserPasswordRequest req(string(pwReq->username), string(pwReq->passwd));
		req.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err)
	
	return -1;
}

ssize_t S6M_PasswdReq_Parse(uint8_t *buf, size_t size, struct S6M_PasswdReq **ppwReq, enum S6M_Error *err)
{
	char *username = NULL;
	char *passwd = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		UserPasswordRequest req(&bb);
		
		username = strdup(req.getUsername().c_str());
		if (!username)
			throw bad_alloc();
		passwd = strdup(req.getUsername().c_str());
		if (!username)
			throw bad_alloc();
		
		S6M_PasswdReq *pwReq = new S6M_PasswdReq();
		pwReq->username = username;
		pwReq->passwd = passwd;
		
		*ppwReq = pwReq;
		return bb.getUsed();
	}
	S6M_CATCH(err)
	
	free(username);
	free(passwd);
	return -1;
}

void S6M_PasswdReq_Free(struct S6M_PasswdReq *pwReq)
{
	free(pwReq->username);
	free(pwReq->passwd);
	delete pwReq;
}

/*
 * S6M_PasswdReply_*
 */

ssize_t S6M_PasswdReply_Packed_Size(const struct S6M_PasswdReply *pwReply, enum S6M_Error *err)
{
	(void) pwReply; (void)err;
	return UserPasswordReply::packedSize();
}

ssize_t S6M_PasswdReply_Pack(const struct S6M_PasswdReply *pwReply, uint8_t *buf, int size, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		
		UserPasswordReply rep(pwReply->success);
		rep.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err)
	
	return -1;
}

ssize_t S6M_PasswdReply_Parse(uint8_t *buf, size_t size, S6M_PasswdReply **ppwReply, enum S6M_Error *err)
{
	try
	{
		ByteBuffer bb(buf, size);
		UserPasswordReply rep(&bb);
		
		S6M_PasswdReply *pwReply = new S6M_PasswdReply();
		pwReply->success = rep.isSuccessful();
		
		*ppwReply = pwReply;
		return bb.getUsed();
	}
	S6M_CATCH(err)
	
	return -1;
}

void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply)
{
	delete pwReply;
}
