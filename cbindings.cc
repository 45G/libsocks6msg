#include <stdlib.h>
#include <string.h>
#include <list>
#include <set>
#include <memory>
#include <stdexcept>
#include "socks6msg.h"
#include "socks6msg.hh"
#include "sanity.hh"

using namespace std;
using namespace S6M;

#define S6M_CATCH(err) \
	catch (EndOfBufferException &) \
	{ \
		(err) = S6M_ERR_BUFFER; \
	} \
	catch (BadVersionException &) \
	{ \
		(err) = S6M_ERR_OTHERVER; \
	} \
	catch (BadAddressTypeException &) \
	{ \
		(err) = S6M_ERR_ADDRTYPE; \
	} \
	catch (invalid_argument &) \
	{ \
		(err) = S6M_ERR_INVALID; \
	} \
	catch (logic_error &) \
	{ \
		(err) = S6M_ERR_INVALID; \
	} \
	catch (bad_alloc &) \
	{ \
		(err) = S6M_ERR_ALLOC; \
	} \
	catch (...) \
	{ \
		(err) = S6M_ERR_UNSPEC; \
	}

struct S6M_PrivateClutter
{
	shared_ptr<string> domain;
	vector<S6M_StackOption> stackOpts;
	vector<uint8_t> sessionID;
	vector<SOCKS6Method> knownMethods;
	shared_ptr<string> username;
	shared_ptr<string> password;
};

/*
 * S6m_Addr
 */

static void S6M_Addr_Fill(S6M_Address *cAddr, const Address &cppAddr, S6M_PrivateClutter *clutter)
{
	cAddr->type = cppAddr.getType();
	
	switch (cppAddr.getType())
	{
	case SOCKS6_ADDR_IPV4:
		cAddr->ipv4 = cppAddr.getIPv4();
		break;
		
	case SOCKS6_ADDR_IPV6:
		cAddr->ipv6 = cppAddr.getIPv6();
		break;
		
	case SOCKS6_ADDR_DOMAIN:
		clutter->domain = cppAddr.getDomain();
		cAddr->domain = clutter->domain->c_str();
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
		return Address(make_shared<string>(cAddr->domain));
	}
	
	throw invalid_argument("Bad address type");
}

template <typename SET>
static void fillStackOptions(const SET *set, list<S6M_StackOption> *stackOpts)
{
	static const vector<SOCKS6StackLeg> LEGS = { SOCKS6_STACK_LEG_CLIENT_PROXY, SOCKS6_STACK_LEG_PROXY_REMOTE };
	
	for (SOCKS6StackLeg leg: LEGS)
	{
		auto value = set->get(leg);
		if (!value)
			continue;
		
		S6M_StackOption opt { leg, SET::Option::LEVEL, SET::Option::CODE, value.value() };
		stackOpts->push_back(opt);
	}
}

/*
 * S6m_OptionSet
 */

static void S6M_OptionSet_Fill(S6M_OptionSet *cSet, const OptionSet *cppSet, S6M_PrivateClutter *clutter)
{
	list<S6M_StackOption> stackOpts;
	fillStackOptions(&cppSet->stack.tos,     &stackOpts);
	fillStackOptions(&cppSet->stack.tfo,     &stackOpts);
	fillStackOptions(&cppSet->stack.mp,      &stackOpts);
	fillStackOptions(&cppSet->stack.backlog, &stackOpts);
	if (!stackOpts.empty())
	{
		clutter->stackOpts.reserve(stackOpts.size());
		int i = 0;
		for (const S6M_StackOption &opt: stackOpts)
			clutter->stackOpts[i++] = opt;
		cSet->stack.options = clutter->stackOpts.data();
	}
	else
	{
		cSet = nullptr;
	}
	
	if (cppSet->session.requested())
		cSet->session.request = 1;
	if (cppSet->session.tornDown())
		cSet->session.tearDown = 1;
	if (cppSet->session.getID())
	{
		clutter->sessionID = *(cppSet->session.getID());
		cSet->session.id = clutter->sessionID.data();
		cSet->session.idLength = clutter->sessionID.size();
	}
	if (cppSet->session.isOK())
		cSet->session.ok = 1;
	if (cppSet->session.rejected())
		cSet->session.rejected = 1;
	if (cppSet->session.isUntrusted())
		cSet->session.untrusted = 1;
	
	cSet->idempotence.request = cppSet->idempotence.requestedSize();
	cSet->idempotence.spend = (bool)cppSet->idempotence.getToken();
	cSet->idempotence.token = cppSet->idempotence.getToken().value_or(0);
	cSet->idempotence.windowBase = cppSet->idempotence.getAdvertised().first;
	cSet->idempotence.windowSize = cppSet->idempotence.getAdvertised().second;
	cSet->idempotence.reply = cppSet->idempotence.getReply().has_value();
	cSet->idempotence.accepted = cppSet->idempotence.getReply().value_or(false);
	
	if (!cppSet->authMethods.getAdvertised()->empty())
	{
		clutter->knownMethods.reserve(cppSet->authMethods.getAdvertised()->size());
		for (SOCKS6Method method: *(cppSet->authMethods.getAdvertised()))
			clutter->knownMethods.push_back(method);
		cSet->authMethods.known = clutter->knownMethods.data();
	}
	cSet->authMethods.initialDataLen = cppSet->authMethods.getInitialDataLen();
	cSet->authMethods.selected = cppSet->authMethods.getSelected();
	
	if (cppSet->userPassword.getUsername() && cppSet->userPassword.getUsername()->length() > 0)
	{
		clutter->username = cppSet->userPassword.getUsername();
		clutter->password = cppSet->userPassword.getPassword();
		cSet->userPassword.username = clutter->username->c_str();
		cSet->userPassword.passwd = clutter->password->c_str();
	}
	if (cppSet->userPassword.getReply().has_value())
	{
		cSet->userPassword.replied = 1;
		cSet->userPassword.success = cppSet->userPassword.getReply().value();
	}
}

static void S6M_OptionSet_Flush(OptionSet *cppSet, const S6M_OptionSet *cSet)
{
	for (int i = 0; i < cSet->stack.count; i++)
	{
		S6M_StackOption *option = &cSet->stack.options[i];
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
	
	if (cSet->session.request)
		cppSet->session.request();
	if (cSet->session.tearDown)
		cppSet->session.tearDown();
	if (cSet->session.idLength)
		cppSet->session.setID(vector<uint8_t>(cSet->session.id, cSet->session.id + cSet->session.idLength));
	if (cSet->session.ok)
		cppSet->session.signalOK();
	if (cSet->session.rejected)
		cppSet->session.signalReject();
	if (cSet->session.untrusted)
		cppSet->session.setUntrusted();
	
	if (cSet->idempotence.request > 0)
		cppSet->idempotence.request(cSet->idempotence.request);
	if (cSet->idempotence.spend)
		cppSet->idempotence.setToken(cSet->idempotence.token);
	if (cSet->idempotence.windowSize > 0)
		cppSet->idempotence.advertise({ cSet->idempotence.windowBase, cSet->idempotence.windowSize });
	if (cSet->idempotence.reply)
		cppSet->idempotence.setReply(cSet->idempotence.accepted);
	
	if (cSet->authMethods.known)
	{
		set<SOCKS6Method> methods;
		
		for (int i = 0; i < cSet->authMethods.knownMethodCount; i++)
			methods.insert((SOCKS6Method)cSet->authMethods.known[i]);
		cppSet->authMethods.advertise(methods, cSet->authMethods.initialDataLen);
	}
	if (cSet->authMethods.selected != SOCKS6_METHOD_NOAUTH)
		cppSet->authMethods.select(cSet->authMethods.selected);
	
	if (cSet->userPassword.username || cSet->userPassword.passwd)
		cppSet->userPassword.setCredentials(make_shared<string>(cSet->userPassword.username), make_shared<string>(cSet->userPassword.passwd));
	if (cSet->userPassword.replied)
		cppSet->userPassword.setReply(cSet->userPassword.success);
}

/*
 * S6M_Request_*
 */

struct S6M_RequestExtended: public S6M_Request
{
	S6M_PrivateClutter clutter;
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
		
		req->code = cppReq.code;
		S6M_Addr_Fill(&req->addr, cppReq.address, &req->clutter);
		req->port = cppReq.port;
		S6M_OptionSet_Fill(&req->optionSet, &cppReq.options, &req->clutter);
		
		*preq = req;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (req)
		S6M_Request_free(req);
	return err;
}

void S6M_Request_free(S6M_Request *req)
{
	delete (S6M_RequestExtended * )req;
}

/*
 * S6M_AuthReply_*
 */

struct S6M_AuthReplyExtended: public S6M_AuthReply
{
	S6M_PrivateClutter clutter;
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
		
		authReply->code = cppAuthReply.code;
		S6M_OptionSet_Fill(&authReply->optionSet, &cppAuthReply.options, &authReply->clutter);
		
		*pauthReply = authReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (authReply)
		S6M_AuthReply_free(authReply);
	return err;
}

void S6M_AuthReply_free(S6M_AuthReply *authReply)
{
	delete (S6M_AuthReplyExtended *)authReply;
}


/*
 * S6M_OpReply_*
 */

struct S6M_OpReplyExtended: public S6M_OpReply
{
	S6M_PrivateClutter clutter;
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
		
		opReply->code = cppOpReply.code;
		S6M_Addr_Fill(&opReply->addr, cppOpReply.address, &opReply->clutter);
		opReply->port = cppOpReply.port;
		S6M_OptionSet_Fill(&opReply->optionSet, &cppOpReply.options, &opReply->clutter);
		
		*popReply = opReply;
		return bb.getUsed();
	}
	S6M_CATCH(err);
	
	if (opReply)
		S6M_OpReply_free(opReply);
	return err;
}


void S6M_OpReply_free(S6M_OpReply *opReply)
{
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
		UserPasswordRequest req(make_shared<string>(pwReq->username), make_shared<string>(pwReq->passwd));
		
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
		
		UserPasswordRequest req(make_shared<string>(pwReq->username), make_shared<string>(pwReq->passwd));
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
		
		pwReq->username = pwReq->cppReq.username->getStr()->c_str();
		pwReq->passwd   = pwReq->cppReq.password->getStr()->c_str();
		
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
		pwReply->success = rep.success;
		
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
