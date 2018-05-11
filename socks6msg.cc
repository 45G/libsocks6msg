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

static void S6M_Addr_Fill(S6M_Addr *cAddr, const Address *cppAddr)
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
		cAddr->domain = strdup(cppAddr->getDomain().c_str());
		if (cAddr->domain == NULL)
			throw bad_alloc();
		break;
	}
}

static Address S6M_Addr_Flush(const S6M_Addr *cAddr)
{
	switch (cAddr->type)
	{
	case SOCKS6_ADDR_IPV4:
		return Address(cAddr->ipv4);
		
	case SOCKS6_ADDR_IPV6:
		return Address(cAddr->ipv6);
		
	case SOCKS6_ADDR_DOMAIN:
		return Address(string(cAddr->domain));
	}
	
	throw InvalidFieldException();
}

static void S6M_Addr_Cleanup(struct S6M_Addr *addr)
{
	free(addr->domain);
}

/*
 * S6m_OptionSet
 */

static void S6M_OptionSet_Fill(S6M_OptionSet *cSet, const OptionSet *cppSet)
{
	cSet->tfo = cppSet->getTFO();
	cSet->mptcp = cppSet->getMPTCP();
	
	cSet->mptcpSched.clientProxy = cppSet->getClientProxySched();
	cSet->mptcpSched.proxyServer = cppSet->getProxyServerSched();
	
	cSet->idempotence.request = cppSet->requestedTokenWindow();
	cSet->idempotence.spend = cppSet->expenditureAttempted();
	if (cSet->idempotence.spend)
		cSet->idempotence.token = cppSet->getToken();
	if (cppSet->advetisedTokenWindow())
	{
		cSet->idempotence.windowBase = cppSet->getTokenWindowBase();
		cSet->idempotence.windowSize = cppSet->getTokenWindowSize();
	}
	cSet->idempotence.replyCode = cppSet->getExpenditureReplyCode();
	
	int i = 0;
	cSet->knownMethods = new SOCKS6Method[cppSet->getKnownMethods()->size()];
	BOOST_FOREACH(SOCKS6Method method, *(cppSet->getKnownMethods()))
	{
		if (method == SOCKS6_METHOD_NOAUTH)
			continue;
		
		cSet->knownMethods[i] = method;
		i++;
	}
	cSet->knownMethods[i] = SOCKS6_METHOD_NOAUTH;
	
	if (cppSet->getUsername()->length() > 0)
	{
		cSet->userPasswdAuth.username = strdup(cppSet->getUsername()->c_str());
		if (cSet->userPasswdAuth.username == NULL)
			throw bad_alloc();
		cSet->userPasswdAuth.username = strdup(cppSet->getPassword()->c_str());
		if (cSet->userPasswdAuth.passwd == NULL)
			throw bad_alloc();
	}
}

static void S6M_OptionSet_Flush(OptionSet *cppSet, const S6M_OptionSet *cSet)
{
	if (cSet->tfo)
		cppSet->setTFO();
	if (cSet->mptcp)
		cppSet->setMPTCP();
	
	if (cSet->mptcpSched.clientProxy > 0)
		cppSet->setClientProxySched(cSet->mptcpSched.clientProxy);
	if (cSet->mptcpSched.proxyServer > 0)
		cppSet->setProxyServerSched(cSet->mptcpSched.proxyServer);
	
	if (cSet->idempotence.request)
		cppSet->requestTokenWindow();
	if (cSet->idempotence.spend)
		cppSet->spendToken(cSet->idempotence.token);
	if (cSet->idempotence.windowSize > 0)
		cppSet->advetiseTokenWindow(cSet->idempotence.windowBase, cSet->idempotence.windowSize);
	if (cSet->idempotence.replyCode > 0)
		cppSet->replyToExpenditure(cSet->idempotence.replyCode);
	
	if (cSet->knownMethods != NULL)
	{
		for (SOCKS6Method *method = cSet->knownMethods; *method != SOCKS6_METHOD_NOAUTH; method++)
			cppSet->advertiseMethod(*method);
	}
	
	if (cSet->userPasswdAuth.username != NULL || cSet->userPasswdAuth.passwd != NULL)
		cppSet->attemptUserPasswdAuth(string(cSet->userPasswdAuth.username), string(cSet->userPasswdAuth.passwd));
}

static void S6M_OptionSet_Cleanup(struct S6M_OptionSet *optionSet)
{
	delete optionSet->knownMethods;
	free(optionSet->userPasswdAuth.username);
	free(optionSet->userPasswdAuth.passwd);
}

/*
 * S6M_Request_*
 */

ssize_t S6M_Request_Packed_Size(const struct S6M_Request *req)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&req->addr);
		OptionSet optSet(OptionSet::M_REQ);
		S6M_OptionSet_Flush(&optSet, &req->optionSet);
		Request cppReq(req->code, addr, req->port, optSet, req->initialDataLen);
		
		return cppReq.packedSize();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_Request_Pack(const struct S6M_Request *req, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		Address addr = S6M_Addr_Flush(&req->addr);
		OptionSet optSet(OptionSet::M_REQ);
		S6M_OptionSet_Flush(&optSet, &req->optionSet);
		Request cppReq(req->code, addr, req->port, optSet, req->initialDataLen);
		cppReq.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_Request_Parse(uint8_t *buf, size_t size, S6M_Request **preq)
{
	S6M_Error err;
	S6M_Request *req = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		Request cppReq(&bb);
		
		req = new S6M_Request();
		memset(req, 0, sizeof(S6M_Request));
		
		req->code = cppReq.getCommandCode();
		S6M_Addr_Fill(&req->addr, cppReq.getAddress());
		req->port = cppReq.getPort();
		req->initialDataLen = cppReq.getInitialDataLen();
		S6M_OptionSet_Fill(&req->optionSet, cppReq.getOptionSet());
		
		*preq = req;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (req != NULL)
		S6M_Request_Free(req);
	return err;
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

ssize_t S6M_AuthReply_Packed_Size(const struct S6M_AuthReply *authReply)
{
	S6M_Error err;
	
	try
	{
		OptionSet optSet(OptionSet::M_AUTH_REP);
		S6M_OptionSet_Flush(&optSet, &authReply->optionSet);
		AuthenticationReply cppAuthReply(authReply->code, authReply->method, optSet);
		
		return cppAuthReply.packedSize();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_AuthReply_Pack(const struct S6M_AuthReply *authReply, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		OptionSet optSet(OptionSet::M_AUTH_REP);
		S6M_OptionSet_Flush(&optSet, &authReply->optionSet);
		AuthenticationReply cppAuthReply(authReply->code, authReply->method, optSet);
		cppAuthReply.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_AuthReply_Parse(uint8_t *buf, size_t size, S6M_AuthReply **pauthReply)
{
	S6M_Error err;
	S6M_AuthReply *authReply = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		AuthenticationReply cppAuthReply(&bb);
		
		authReply = new S6M_AuthReply();
		memset(authReply, 0, sizeof(S6M_AuthReply));
		
		authReply->code = cppAuthReply.getReplyCode();
		authReply->method = cppAuthReply.getMethod();
		S6M_OptionSet_Fill(&authReply->optionSet, cppAuthReply.getOptionSet());
		
		*pauthReply = authReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (authReply != NULL)
		S6M_AuthReply_Free(authReply);
	return err;
}

void S6M_AuthReply_Free(struct S6M_AuthReply *authReply)
{
	S6M_OptionSet_Cleanup(&authReply->optionSet);
	delete authReply;
}


/*
 * S6M_OpReply_*
 */

ssize_t S6M_OpReply_Packed_Size(const struct S6M_OpReply *opReply)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&opReply->addr);
		OptionSet optSet(OptionSet::M_OP_REP);
		S6M_OptionSet_Flush(&optSet, &opReply->optionSet);
		OperationReply cppOpReply(opReply->code, addr, opReply->port, opReply->initDataOff, optSet);
		
		return cppOpReply.packedSize();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_OpReply_Pack(const struct S6M_OpReply *opReply, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		Address addr = S6M_Addr_Flush(&opReply->addr);
		OptionSet optSet(OptionSet::M_OP_REP);
		S6M_OptionSet_Flush(&optSet, &opReply->optionSet);
		OperationReply cppOpReply(opReply->code, addr, opReply->port, opReply->initDataOff, optSet);
		cppOpReply.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}


ssize_t S6M_OpReply_Parse(uint8_t *buf, size_t size, S6M_OpReply **popReply)
{
	S6M_Error err;
	S6M_OpReply *opReply = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		OperationReply cppOpReply(&bb);
		
		opReply = new S6M_OpReply();
		memset(opReply, 0, sizeof(S6M_OpReply));
		
		opReply->code = cppOpReply.getCode();
		S6M_Addr_Fill(&opReply->addr, cppOpReply.getAddress());
		opReply->port = cppOpReply.getPort();
		opReply->initDataOff = cppOpReply.getInitDataOff();
		S6M_OptionSet_Fill(&opReply->optionSet, cppOpReply.getOptionSet());
		
		*popReply = opReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (opReply != NULL)
		S6M_OpReply_Free(opReply);
	return err;
}


void S6M_OpReply_Free(struct S6M_OpReply *opReply)
{
	S6M_Addr_Cleanup(&opReply->addr);
	S6M_OptionSet_Cleanup(&opReply->optionSet);
	delete opReply;
}

/*
 * S6M_PasswdReq_*
 */

ssize_t S6M_PasswdReq_Packed_Size(const struct S6M_PasswdReq *pwReq)
{
	S6M_Error err;
	
	try
	{
		UserPasswordRequest req(string(pwReq->username), string(pwReq->passwd));
		
		return req.packedSize();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_PasswdReq_Pack(const struct S6M_PasswdReq *pwReq, uint8_t *buf, size_t size)
{
	S6M_Error err;
	
	try
	{
		ByteBuffer bb(buf, size);
		
		UserPasswordRequest req(string(pwReq->username), string(pwReq->passwd));
		req.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_PasswdReq_Parse(uint8_t *buf, size_t size, struct S6M_PasswdReq **ppwReq)
{
	S6M_Error err;
	char *username = NULL;
	char *passwd = NULL;
	
	try
	{
		ByteBuffer bb(buf, size);
		UserPasswordRequest req(&bb);
		
		username = strdup(req.getUsername().c_str());
		if (username == NULL)
			throw bad_alloc();
		passwd = strdup(req.getUsername().c_str());
		if (passwd == NULL)
			throw bad_alloc();
		
		S6M_PasswdReq *pwReq = new S6M_PasswdReq();
		pwReq->username = username;
		pwReq->passwd = passwd;
		
		*ppwReq = pwReq;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	free(username);
	free(passwd);
	return err;
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

ssize_t S6M_PasswdReply_Packed_Size(const struct S6M_PasswdReply *pwReply)
{
	(void)pwReply;
	
	return UserPasswordReply::packedSize();
}

ssize_t S6M_PasswdReply_Pack(const struct S6M_PasswdReply *pwReply, uint8_t *buf, size_t size)
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

ssize_t S6M_PasswdReply_Parse(uint8_t *buf, size_t size, S6M_PasswdReply **ppwReply)
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

void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply)
{
	delete pwReply;
}

/*
 * S6M_Error_*
 */

const char *S6M_Error_Msg(S6M_Error err)
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
