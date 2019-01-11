#include <stdlib.h>
#include <string.h>
#include <list>
#include <set>
#include <boost/foreach.hpp>
#include <memory>
#include "socks6msg.h"
#include "socks6msg.hh"

using namespace std;
using namespace boost;
using namespace S6M;

#define S6M_CATCH(err) \
	catch (InvalidFieldException) \
	{ \
		(err) = S6M_ERR_INVALID; \
	} \
	catch (EndOfBufferException) \
	{ \
		(err) = S6M_ERR_BUFFER; \
	} \
	catch (BadVersionException) \
	{ \
		(err) = S6M_ERR_OTHERVER; \
	} \
	catch (bad_alloc) \
	{ \
		(err) = S6M_ERR_ALLOC; \
	} \
	catch (...) \
	{ \
		(err) = S6M_ERR_UNSPEC; \
	}

/*
 * S6m_Addr
 */

static void S6M_Addr_Fill(S6M_Address *cAddr, const Address *cppAddr)
{
	cAddr->type = cppAddr->getType();
	
	switch (cppAddr->getType())
	{
	case SOCKS6_ADDR_IPV4:
		cAddr->ipv4 = cppAddr->getIPv4();
		break;
		
	case SOCKS6_ADDR_IPV6:
		cAddr->ipv6 = cppAddr->getIPv6();
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		cAddr->domain = cppAddr->getDomain()->c_str();
		if (cAddr->domain == NULL)
			throw bad_alloc();
		break;
	}
}

static Address S6M_Addr_Flush(const S6M_Address *cAddr)
{
	switch (cAddr->type)
	{
	case SOCKS6_ADDR_IPV4:
		return Address(cAddr->ipv4);
		
	case SOCKS6_ADDR_IPV6:
		return Address(cAddr->ipv6);
		
	case SOCKS6_ADDR_DOMAIN:
		return Address(std::shared_ptr<string>(new string(cAddr->domain)));
	}
	
	throw InvalidFieldException();
}

/*
 * S6m_OptionSet
 */

static void S6M_OptionSet_Fill(S6M_OptionSet *cSet, const OptionSet *cppSet)
{
	cSet->tos.clientProxy = cppSet->getClientProxyTOS();
	cSet->tos.proxyRemote = cppSet->getProxyRemoteTOS();

	cSet->tfo = cppSet->getTFO();
	cSet->mptcp = cppSet->getMPTCP();
	
	cSet->mptcpSched.clientProxy = cppSet->getClientProxySched();
	cSet->mptcpSched.proxyServer = cppSet->getProxyRemoteSched();

	cSet->backlog = cppSet->getBacklog();
	
	cSet->idempotence.request = cppSet->requestedTokenWindow();
	cSet->idempotence.spend = cppSet->hasToken();
	if (cSet->idempotence.spend)
		cSet->idempotence.token = cppSet->getToken();
	cSet->idempotence.windowBase = cppSet->getTokenWindowBase();
	cSet->idempotence.windowSize = cppSet->getTokenWindowSize();
	cSet->idempotence.replyCode = cppSet->getExpenditureReply();
	
	int i = 0;
	cSet->knownMethods = new SOCKS6Method[cppSet->getAdvertisedMethods()->size()];
	BOOST_FOREACH(SOCKS6Method method, *(cppSet->getAdvertisedMethods()))
	{
		if (method == SOCKS6_METHOD_NOAUTH)
			continue;
		
		cSet->knownMethods[i] = method;
		i++;
	}
	cSet->knownMethods[i] = SOCKS6_METHOD_NOAUTH;
	cSet->initialDataLen = cppSet->getInitialDataLen();
	
	if (cppSet->getUsername().get() != NULL && cppSet->getUsername()->length() > 0)
	{
		cSet->userPasswdAuth.username = cppSet->getUsername()->c_str();
		if (cSet->userPasswdAuth.username == NULL)
			throw bad_alloc();
		cSet->userPasswdAuth.username = cppSet->getPassword()->c_str();
		if (cSet->userPasswdAuth.passwd == NULL)
			throw bad_alloc();
	}
}

static void S6M_OptionSet_Flush(OptionSet *cppSet, const S6M_OptionSet *cSet)
{
	if (cSet->tos.clientProxy > 0)
		cppSet->setClientProxyTOS(cSet->tos.clientProxy);
	if (cSet->tos.proxyRemote > 0)
		cppSet->setProxyRemoteTOS(cSet->tos.proxyRemote);

	if (cSet->tfo > 0)
		cppSet->setTFO(cSet->tfo);
	if (cSet->mptcp)
		cppSet->setMPTCP();
	
	if (cSet->mptcpSched.clientProxy > 0)
		cppSet->setClientProxySched(cSet->mptcpSched.clientProxy);
	if (cSet->mptcpSched.proxyServer > 0)
		cppSet->setProxyRemoteSched(cSet->mptcpSched.proxyServer);

	if (cSet->backlog > 0)
		cppSet->setBacklog(cSet->backlog);
	
	if (cSet->idempotence.request > 0)
		cppSet->requestTokenWindow(cSet->idempotence.request);
	if (cSet->idempotence.spend)
		cppSet->setToken(cSet->idempotence.token);
	if (cSet->idempotence.windowSize > 0)
		cppSet->setTokenWindow(cSet->idempotence.windowBase, cSet->idempotence.windowSize);
	if (cSet->idempotence.replyCode > 0)
		cppSet->setExpenditureReply(cSet->idempotence.replyCode);
	
	if (cSet->knownMethods != NULL)
	{
		for (SOCKS6Method *method = cSet->knownMethods; *method != SOCKS6_METHOD_NOAUTH; method++)
			cppSet->advertiseMethod(*method);
		cppSet->setInitialDataLen(cSet->initialDataLen);
	}
	
	if (cSet->userPasswdAuth.username != NULL || cSet->userPasswdAuth.passwd != NULL)
		cppSet->setUsernamePassword(std::shared_ptr<string>(new string(cSet->userPasswdAuth.username)), std::shared_ptr<string>(new string(cSet->userPasswdAuth.passwd)));
}

static void S6M_OptionSet_Cleanup(S6M_OptionSet *optionSet)
{
	delete optionSet->knownMethods;
}

/*
 * S6M_Request_*
 */

struct S6M_RequestExtended: public S6M_Request
{
	Address cppAddr;
	std::shared_ptr<string> cppUsername;
	std::shared_ptr<string> cppPasswd;
};

ssize_t S6M_Request_packedSize(const S6M_Request *req)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&req->addr);
		Request cppReq(req->code, addr, req->port);
		S6M_OptionSet_Flush(cppReq.getOptionSet(), &req->optionSet);
		
		return cppReq.packedSize();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_Request_pack(const S6M_Request *req, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		Address addr = S6M_Addr_Flush(&req->addr);
		Request cppReq(req->code, addr, req->port);
		S6M_OptionSet_Flush(cppReq.getOptionSet(), &req->optionSet);
		cppReq.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_Request_parse(uint8_t *buf, size_t size, S6M_Request **preq)
{
	S6M_Error err;
	S6M_RequestExtended *req = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		Request cppReq(&bb);
		
		req = new S6M_RequestExtended();
		memset((S6M_Request *)req, 0, sizeof(S6M_Request));
		req->cppAddr = *(cppReq.getAddress());
		req->cppUsername = cppReq.getOptionSet()->getUsername();
		req->cppPasswd = cppReq.getOptionSet()->getPassword();
		
		req->code = cppReq.getCommandCode();
		S6M_Addr_Fill(&req->addr, cppReq.getAddress());
		req->port = cppReq.getPort();
		S6M_OptionSet_Fill(&req->optionSet, cppReq.getOptionSet());
		
		*preq = req;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (req != NULL)
		S6M_Request_free(req);
	return err;
}

void S6M_Request_free(S6M_Request *req)
{
	S6M_OptionSet_Cleanup(&req->optionSet);
	delete req;
}

/*
 * S6M_AuthReply_*
 */

struct S6M_AuthReplyExtended: public S6M_AuthReply
{
	std::shared_ptr<string> cppUsername;
	std::shared_ptr<string> cppPasswd;
};

ssize_t S6M_AuthReply_packedSize(const S6M_AuthReply *authReply)
{
	S6M_Error err;
	
	try
	{
		AuthenticationReply cppAuthReply(authReply->code, authReply->method);
		S6M_OptionSet_Flush(cppAuthReply.getOptionSet(), &authReply->optionSet);
		
		return cppAuthReply.packedSize();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_AuthReply_pack(const S6M_AuthReply *authReply, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		AuthenticationReply cppAuthReply(authReply->code, authReply->method);
		S6M_OptionSet_Flush(cppAuthReply.getOptionSet(), &authReply->optionSet);
		cppAuthReply.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_AuthReply_parse(uint8_t *buf, size_t size, S6M_AuthReply **pauthReply)
{
	S6M_Error err;
	S6M_AuthReplyExtended *authReply = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		AuthenticationReply cppAuthReply(&bb);
		
		authReply = new S6M_AuthReplyExtended();
		memset((S6M_AuthReply *)authReply, 0, sizeof(S6M_AuthReply));
		authReply->cppUsername = cppAuthReply.getOptionSet()->getUsername();
		authReply->cppPasswd = cppAuthReply.getOptionSet()->getPassword();
		
		authReply->code = cppAuthReply.getReplyCode();
		authReply->method = cppAuthReply.getMethod();
		S6M_OptionSet_Fill(&authReply->optionSet, cppAuthReply.getOptionSet());
		
		*pauthReply = authReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (authReply != NULL)
		S6M_AuthReply_free(authReply);
	return err;
}

void S6M_AuthReply_free(S6M_AuthReply *authReply)
{
	S6M_OptionSet_Cleanup(&authReply->optionSet);
	delete (S6M_AuthReply *)authReply;
}


/*
 * S6M_OpReply_*
 */

struct S6M_OpReplyExtended: public S6M_OpReply
{
	Address cppAddr;
	std::shared_ptr<string> cppUsername;
	std::shared_ptr<string> cppPasswd;
};

ssize_t S6M_OpReply_packedSize(const S6M_OpReply *opReply)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&opReply->addr);
		OperationReply cppOpReply(opReply->code, addr, opReply->port);
		S6M_OptionSet_Flush(cppOpReply.getOptionSet(), &opReply->optionSet);
		
		return cppOpReply.packedSize();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_OpReply_pack(const S6M_OpReply *opReply, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		Address addr = S6M_Addr_Flush(&opReply->addr);
		OperationReply cppOpReply(opReply->code, addr, opReply->port);
		S6M_OptionSet_Flush(cppOpReply.getOptionSet(), &opReply->optionSet);
		cppOpReply.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}


ssize_t S6M_OpReply_parse(uint8_t *buf, size_t size, S6M_OpReply **popReply)
{
	S6M_Error err;
	S6M_OpReplyExtended *opReply = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		OperationReply cppOpReply(&bb);
		
		opReply = new S6M_OpReplyExtended();
		memset((S6M_OpReply *)opReply, 0, sizeof(S6M_OpReply));
		opReply->cppAddr = *(cppOpReply.getAddress());
		opReply->cppUsername = cppOpReply.getOptionSet()->getUsername();
		opReply->cppPasswd = cppOpReply.getOptionSet()->getPassword();
		
		opReply->code = cppOpReply.getCode();
		S6M_Addr_Fill(&opReply->addr, cppOpReply.getAddress());
		opReply->port = cppOpReply.getPort();
		S6M_OptionSet_Fill(&opReply->optionSet, cppOpReply.getOptionSet());
		
		*popReply = opReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (opReply != NULL)
		S6M_OpReply_free(opReply);
	return err;
}


void S6M_OpReply_free(S6M_OpReply *opReply)
{
	S6M_OptionSet_Cleanup(&opReply->optionSet);
	delete (S6M_OpReplyExtended *)opReply;
}

/*
 * S6M_PasswdReq_*
 */

struct S6M_PasswdReqExtended: public S6M_PasswdReq
{
	UserPasswordRequest cppReq;
	
	S6M_PasswdReqExtended(ByteBuffer *bb)
		: cppReq(bb) {}
};

ssize_t S6M_PasswdReq_packedSize(const S6M_PasswdReq *pwReq)
{
	S6M_Error err;
	
	try
	{
		UserPasswordRequest req(std::shared_ptr<string>(new string(pwReq->username)), std::shared_ptr<string>(new string(pwReq->passwd)));
		
		return req.packedSize();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_PasswdReq_pack(const S6M_PasswdReq *pwReq, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		UserPasswordRequest req(std::shared_ptr<string> (new string(pwReq->username)), std::shared_ptr<string>(new string(pwReq->passwd)));
		req.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_PasswdReq_parse(uint8_t *buf, size_t size, S6M_PasswdReq **ppwReq)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		S6M_PasswdReqExtended *pwReq = new S6M_PasswdReqExtended(&bb);
		
		pwReq->username = pwReq->cppReq.getUsername()->c_str();
		pwReq->passwd = pwReq->cppReq.getPassword()->c_str();
		
		*ppwReq = pwReq;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}

void S6M_PasswdReq_free(S6M_PasswdReq *pwReq)
{
	delete (S6M_PasswdReqExtended *)pwReq;
}

/*
 * S6M_PasswdReply_*
 */

ssize_t S6M_PasswdReply_packedSize(const S6M_PasswdReply *pwReply)
{
	(void)pwReply;
	
	return UserPasswordReply::packedSize();
}

ssize_t S6M_PasswdReply_pack(const S6M_PasswdReply *pwReply, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		UserPasswordReply rep(pwReply->success);
		rep.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_PasswdReply_parse(uint8_t *buf, size_t size, S6M_PasswdReply **ppwReply)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		UserPasswordReply rep(&bb);
		
		S6M_PasswdReply *pwReply = new S6M_PasswdReply();
		pwReply->success = rep.isSuccessful();
		
		*ppwReply = pwReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}

void S6M_PasswdReply_free(S6M_PasswdReply *pwReply)
{
	delete pwReply;
}

/*
 * S6M_Error_*
 */

const char *S6M_Error_msg(S6M_Error err)
{
	switch (err)
	{
	case S6M_ERR_SUCCESS:
		return "Success";
		
	case S6M_ERR_INVALID:
		return "Invalid field";
		
	case S6M_ERR_ALLOC:
		return "Memory allocation failure";
		
	case S6M_ERR_BUFFER:
		return "End of buffer";
		
	case S6M_ERR_OTHERVER:
		return "Unsupported protocol version";
		
	case S6M_ERR_UNSPEC:
		return "Unspecified error";
		
	default:
		return "Not my problem!";
	}
}
