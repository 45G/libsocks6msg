#include <stdlib.h>
#include <string.h>
#include <list>
#include <set>
#include <boost/foreach.hpp>
#include <memory>
#include <stdexcept>
#include "socks6msg.h"
#include "socks6msg.hh"
#include "sanity.hh"

using namespace std;
using namespace S6M;

#define S6M_CATCH(err) \
	catch (invalid_argument &) \
	{ \
		(err) = S6M_ERR_INVALID; \
	} \
	catch (EndOfBufferException &) \
	{ \
		(err) = S6M_ERR_BUFFER; \
	} \
	catch (logic_error &) \
	{ \
		(err) = S6M_ERR_INVALID; \
	} \
	catch (BadVersionException &) \
	{ \
		(err) = S6M_ERR_OTHERVER; \
	} \
	catch (bad_alloc &) \
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
		if (cAddr->domain == nullptr) //TODO: what?
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
		return Address(move(string(cAddr->domain)));
	}
	
	throw invalid_argument("Bad address type");
}

template <typename SET>
static void fillStackOptions(const SET *set, list<S6M_StackOption> *stackOpts)
{
	SOCKS6StackLeg legs[] = { SOCKS6_STACK_LEG_CLIENT_PROXY, SOCKS6_STACK_LEG_PROXY_REMOTE };
	
	for (int i = 0; i < 2; i++)
	{
		auto value = set->get(legs[i]);
		if (!value)
			continue;
		
		S6M_StackOption opt { legs[i], SET::Option::LEVEL, SET::Option::CODE, (int)value.get() };
		stackOpts->push_back(opt);
	}
}

/*
 * S6m_OptionSet
 */

static void S6M_OptionSet_Fill(S6M_OptionSet *cSet, const OptionSet *cppSet)
{
	list<S6M_StackOption> stackOpts;
	fillStackOptions(&cppSet->stack.tos,     &stackOpts);
	fillStackOptions(&cppSet->stack.tfo,     &stackOpts);
	fillStackOptions(&cppSet->stack.mp,      &stackOpts);
	fillStackOptions(&cppSet->stack.backlog, &stackOpts);
	
	if (stackOpts.empty())
	{
		cSet->stackOptions = new S6M_StackOption[stackOpts.size()];
		int i = 0;
		BOOST_FOREACH(S6M_StackOption opt, stackOpts)
		{
			cSet->stackOptions[i] = opt;
			i++;
		}
	}
	else
	{
		cSet = nullptr;
	}
	
	cSet->idempotence.request = cppSet->idempotence.requestedSize();
	cSet->idempotence.spend = (bool)cppSet->idempotence.getToken();
	cSet->idempotence.token = cppSet->idempotence.getToken().get_value_or(0);
	cSet->idempotence.windowBase = cppSet->idempotence.advertisedBase();
	cSet->idempotence.windowSize = cppSet->idempotence.advertisedSize();
	cSet->idempotence.reply = cppSet->idempotence.getReply() == boost::none;
	cSet->idempotence.accepted = cppSet->idempotence.getReply().get_value_or(false);
	
	int i = 0;
	cSet->authMethods.known = new SOCKS6Method[cppSet->authMethods.getAdvertised()->size()];
	BOOST_FOREACH(SOCKS6Method method, *(cppSet->authMethods.getAdvertised()))
	{
		if (method == SOCKS6_METHOD_NOAUTH)
			continue;
		
		cSet->authMethods.known[i] = method;
		i++;
	}
	cSet->authMethods.known[i] = SOCKS6_METHOD_NOAUTH;
	cSet->authMethods.initialDataLen = cppSet->authMethods.getInitialDataLen();
	
	if (cppSet->userPassword.getUsername() != nullptr && cppSet->userPassword.getUsername()->length() > 0)
	{
		cSet->userPassword.username = cppSet->userPassword.getUsername()->c_str();
		if (cSet->userPassword.username == nullptr)
			throw bad_alloc();
		cSet->userPassword.username = cppSet->userPassword.getPassword()->c_str();
		if (cSet->userPassword.passwd == nullptr)
			throw bad_alloc();
	}
}

static void S6M_OptionSet_Flush(OptionSet *cppSet, const S6M_OptionSet *cSet)
{
	for (int i = 0; i < cSet->stackOptionCount; i++)
	{
		S6M_StackOption *option = &cSet->stackOptions[i];
		if (option->level == SOCKS6_STACK_LEVEL_IP)
		{
			if (option->code == SOCKS6_STACK_CODE_TOS)
				cppSet->stack.tos.set(option->leg, option->value);
			else
				throw logic_error("Invalid option");
		}
		else if (option->level == SOCKS6_STACK_LEVEL_TCP)
		{
			if (option->code == SOCKS6_STACK_CODE_TFO)
				cppSet->stack.tfo.set(option->leg, option->value);
			else if (option->code == SOCKS6_STACK_CODE_MP)
				cppSet->stack.mp.set(option->leg, enumCast<SOCKS6MPAvailability>(option->value));
			else if (option->code == SOCKS6_STACK_CODE_BACKLOG)
				cppSet->stack.backlog.set(option->leg, option->value);
			else
				throw logic_error("Invalid option");
		}
		else
		{
			throw logic_error("Invalid option");
		}
	}
	
	if (cSet->idempotence.request > 0)
		cppSet->idempotence.request(cSet->idempotence.request);
	if (cSet->idempotence.spend)
		cppSet->idempotence.setToken(cSet->idempotence.token);
	if (cSet->idempotence.windowSize > 0)
		cppSet->idempotence.advertise(cSet->idempotence.windowBase, cSet->idempotence.windowSize);
	if (cSet->idempotence.reply)
		cppSet->idempotence.setReply(cSet->idempotence.accepted);
	
	if (cSet->authMethods.known != nullptr)
	{
		set<SOCKS6Method> methods;
		
		for (int i = 0; i < cSet->authMethods.knownMethodCount; i++)
			methods.insert((SOCKS6Method)cSet->authMethods.known[i]);
		cppSet->authMethods.advertise(methods, cSet->authMethods.initialDataLen);
	}
	
	if (cSet->userPassword.username != nullptr || cSet->userPassword.passwd != nullptr)
		cppSet->userPassword.setCredentials(move(string(cSet->userPassword.username)), move(string(cSet->userPassword.passwd)));
}

static void S6M_OptionSet_Cleanup(S6M_OptionSet *optionSet)
{
	delete optionSet->authMethods.known;
	delete optionSet->stackOptions;
}

/*
 * S6M_Request_*
 */

struct S6M_RequestExtended: public S6M_Request
{
	Address cppAddr;
	string cppUsername;
	string cppPasswd;
};

ssize_t S6M_Request_packedSize(const S6M_Request *req)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&req->addr);
		Request cppReq(req->code, addr, req->port);
		S6M_OptionSet_Flush(&cppReq.options, &req->optionSet);
		
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
		S6M_OptionSet_Flush(&cppReq.options, &req->optionSet);
		cppReq.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_Request_parse(uint8_t *buf, size_t size, S6M_Request **preq)
{
	S6M_Error err;
	S6M_RequestExtended *req = nullptr;
	
	try
	{
		ByteBuffer bb(buf, size);
		Request cppReq(&bb);
		
		req = new S6M_RequestExtended();
		memset((S6M_Request *)req, 0, sizeof(S6M_Request));
		req->cppAddr = *(cppReq.getAddress());
		req->cppUsername = *cppReq.options.userPassword.getUsername();
		req->cppPasswd = *cppReq.options.userPassword.getPassword();
		
		req->code = cppReq.getCommandCode();
		S6M_Addr_Fill(&req->addr, cppReq.getAddress());
		req->port = cppReq.getPort();
		S6M_OptionSet_Fill(&req->optionSet, &cppReq.options);
		
		*preq = req;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (req != nullptr)
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
	string cppUsername;
	string cppPasswd;
};

ssize_t S6M_AuthReply_packedSize(const S6M_AuthReply *authReply)
{
	S6M_Error err;
	
	try
	{
		AuthenticationReply cppAuthReply(authReply->code);
		S6M_OptionSet_Flush(&cppAuthReply.options, &authReply->optionSet);
		
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
		
		AuthenticationReply cppAuthReply(authReply->code);
		S6M_OptionSet_Flush(&cppAuthReply.options, &authReply->optionSet);
		cppAuthReply.pack(&bb);
		
		return bb.getUsed();
		
	}
	S6M_CATCH(err);
	
	return err;
}

ssize_t S6M_AuthReply_parse(uint8_t *buf, size_t size, S6M_AuthReply **pauthReply)
{
	S6M_Error err;
	S6M_AuthReplyExtended *authReply = nullptr;
	
	try
	{
		ByteBuffer bb(buf, size);
		AuthenticationReply cppAuthReply(&bb);
		
		authReply = new S6M_AuthReplyExtended();
		memset((S6M_AuthReply *)authReply, 0, sizeof(S6M_AuthReply));
		authReply->cppUsername = *cppAuthReply.options.userPassword.getUsername();
		authReply->cppPasswd = *cppAuthReply.options.userPassword.getPassword();
		
		authReply->code = cppAuthReply.getReplyCode();
		S6M_OptionSet_Fill(&authReply->optionSet, &cppAuthReply.options);
		
		*pauthReply = authReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (authReply != nullptr)
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
	string cppUsername;
	string cppPasswd;
};

ssize_t S6M_OpReply_packedSize(const S6M_OpReply *opReply)
{
	S6M_Error err;
	
	try
	{
		Address addr = S6M_Addr_Flush(&opReply->addr);
		OperationReply cppOpReply(opReply->code, addr, opReply->port);
		S6M_OptionSet_Flush(&cppOpReply.options, &opReply->optionSet);
		
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
		S6M_OptionSet_Flush(&cppOpReply.options, &opReply->optionSet);
		cppOpReply.pack(&bb);
		
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	return err;
}


ssize_t S6M_OpReply_parse(uint8_t *buf, size_t size, S6M_OpReply **popReply)
{
	S6M_Error err;
	S6M_OpReplyExtended *opReply = nullptr;
	
	try
	{
		ByteBuffer bb(buf, size);
		OperationReply cppOpReply(&bb);
		
		opReply = new S6M_OpReplyExtended();
		memset((S6M_OpReply *)opReply, 0, sizeof(S6M_OpReply));
		opReply->cppAddr = *(cppOpReply.getAddress());
		opReply->cppUsername = *cppOpReply.options.userPassword.getUsername();
		opReply->cppPasswd = *cppOpReply.options.userPassword.getPassword();
		
		opReply->code = cppOpReply.getCode();
		S6M_Addr_Fill(&opReply->addr, cppOpReply.getAddress());
		opReply->port = cppOpReply.getPort();
		S6M_OptionSet_Fill(&opReply->optionSet, &cppOpReply.options);
		
		*popReply = opReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (opReply != nullptr)
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
		UserPasswordRequest req(move(string(pwReq->username)), move(string(pwReq->passwd)));
		
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
		
		UserPasswordRequest req(move(string(pwReq->username)), move(string(pwReq->passwd)));
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
