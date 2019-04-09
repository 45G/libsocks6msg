#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include "optionset.hh"


using namespace std;
using namespace boost;

namespace S6M
{

#define COMMIT(FIELD, WHAT) \
	ensureVacant(FIELD); \
	(FIELD).reset(WHAT); \
	owner->registerOption((FIELD).get());

template <typename T>
static bool mayAssign(T field, T value)
{
	return (field == (T)0 || field == value);
}

template <typename T>
static bool mayAssign(T field1, T field2, T value)
{
	return mayAssign(field1, value) && mayAssign(field2, value);
}

template <typename T>
static void checkedAssignment(T *field, T value)
{
	if (!mayAssign(*field, value))
		throw invalid_argument("");

	*field = value;
}

template <typename T>
static void checkedAssignment(T *field1, T *field2, T value)
{
	if (!mayAssign(*field1, *field2, value))
		throw invalid_argument("");

	*field1 = value;
	*field2 = value;
}

template <typename T, typename U>
static void checkedAssignment(T *field1, T value1, U *field2, U value2)
{
	if (!mayAssign(*field1, value1))
		throw invalid_argument("");
	if (!mayAssign(*field2, value2))
		throw invalid_argument("");

	*field1 = value1;
	*field2 = value2;
}


void OptionSetBase::enforceMode(OptionSet::Mode mode1) const
{
	if (mode != mode1)
		throw logic_error("Option not available");
}

void OptionSetBase::enforceMode(OptionSet::Mode mode1, OptionSet::Mode mode2) const
{
	if (mode != mode1 && mode != mode2)
		throw logic_error("Option not available");
}

OptionSet::OptionSet(ByteBuffer *bb, Mode mode)
	: OptionSetBase(this, mode), sessionSet(this), idempotenceSet(this)
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	uint16_t optsLen = ntohs(optsHead->optionsLength);
	if (optsLen > SOCKS6_OPTIONS_LENGTH_MAX)
		throw invalid_argument("Bad options length");
	ByteBuffer optsBB(bb->get<uint8_t>(optsLen), optsLen);
	
	while (optsBB.getUsed() < optsBB.getTotalSize())
	{
		SOCKS6Option *opt;
		size_t optLen;

		try
		{
			opt = bb->get<SOCKS6Option>();

			/* bad option length wrecks remaining options */
			optLen = ntohs(opt->len);
			if (optLen < sizeof(SOCKS6Option))
				break;

			bb->get<uint8_t>(optLen - sizeof(SOCKS6Option));
		}
		catch (length_error &)
		{
			break;
		}
		
		try
		{
			Option::incrementalParse(opt, optLen, this);
		}
		catch (invalid_argument &) {}
	}
}

static void cram(const Option &option, SOCKS6Options *optionsHead, ByteBuffer *bb)
{
	option.pack(bb);
	optionsHead->optionsLength += option.packedSize();
}

void OptionSet::pack(ByteBuffer *bb) const
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	optsHead->optionsLength = 0;
	
	if (tfo)
		cram(TFOOption(SOCKS6_STACK_LEG_PROXY_REMOTE, tfoPayload), optsHead, bb);
	if (mptcp)
		cram(MPTCPOption(SOCKS6_STACK_LEG_PROXY_REMOTE, true), optsHead, bb);
	
	if (ipTOS.clientProxy > 0)
	{
		if (ipTOS.proxyRemote == ipTOS.clientProxy)
		{
			cram(TOSOption(SOCKS6_STACK_LEG_BOTH, ipTOS.clientProxy), optsHead, bb);
			goto both_tos_done;
		}
		else
		{
			cram(TOSOption(SOCKS6_STACK_LEG_CLIENT_PROXY, ipTOS.clientProxy), optsHead, bb);
		}
	}
	if (ipTOS.proxyRemote > 0)
		cram(TOSOption(SOCKS6_STACK_LEG_PROXY_REMOTE, ipTOS.proxyRemote), optsHead, bb);

both_tos_done:
	
	if (!methods.advertised.empty())
		cram(AuthMethodOption(methods.initialDataLen, methods.advertised), optsHead, bb);
	
	BOOST_FOREACH(Option *option, options)
	{
		cram(*option, optsHead, bb);
	}
}

size_t OptionSet::packedSize() const
{
	size_t size = sizeof(SOCKS6Options);
	
	if (tfo)
		size += TFOOption(SOCKS6_STACK_LEG_PROXY_REMOTE, tfoPayload).packedSize();
	if (mptcp)
		size += MPTCPOption(SOCKS6_STACK_LEG_PROXY_REMOTE, true).packedSize();
	
	if (ipTOS.clientProxy > 0)
	{
		if (ipTOS.proxyRemote == ipTOS.clientProxy)
		{
			size += TOSOption(SOCKS6_STACK_LEG_BOTH, ipTOS.clientProxy).packedSize();
			goto both_tos_done;
		}
		else
		{
			size += TOSOption(SOCKS6_STACK_LEG_CLIENT_PROXY, ipTOS.clientProxy).packedSize();
		}
	}
	if (ipTOS.proxyRemote > 0)
		size += TOSOption(SOCKS6_STACK_LEG_PROXY_REMOTE, ipTOS.proxyRemote).packedSize();

both_tos_done:
	
	if (!methods.advertised.empty())
		size += AuthMethodOption(methods.initialDataLen, methods.advertised).packedSize();
	
	size += optionsSize;
	
	return size;
}

void OptionSet::setClientProxyTOS(uint8_t tos)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&ipTOS.clientProxy, tos);
}

void OptionSet::setProxyRemoteTOS(uint8_t tos)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&ipTOS.proxyRemote, tos);
}

void OptionSet::setBothTOS(uint8_t tos)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&ipTOS.clientProxy, &ipTOS.proxyRemote, tos);
}

void OptionSet::setTFOPayload(uint16_t payloadSize)
{
	enforceMode(M_REQ);
	if (tfo)
	{
		if (payloadSize != tfoPayload)
			throw invalid_argument("");
	}
	else
	{
		tfo = true;
		tfoPayload = payloadSize;
	}
}

void OptionSet::setMPTCP()
{
	enforceMode(M_OP_REP);
	mptcp = true;
}

void OptionSet::setBacklog(uint16_t backlog)
{
	checkedAssignment(&this->backlog, backlog);
}

void OptionSet::advertiseMethod(SOCKS6Method method)
{
	enforceMode(M_REQ);

	if (method == SOCKS6_METHOD_NOAUTH)
		return;
	if (method == SOCKS6_METHOD_UNACCEPTABLE)
		throw invalid_argument("Bad method");

	methods.advertised.insert(method);
}

void OptionSet::setInitialDataLen(uint16_t initialDataLen)
{
	enforceMode(M_REQ);

	if (initialDataLen > SOCKS6_INITIAL_DATA_MAX)
		throw invalid_argument("Bad initial data length");

	checkedAssignment(&methods.initialDataLen, initialDataLen);
}

void OptionSet::setUsernamePassword(const string &user, const string &passwd)
{
	enforceMode(M_REQ);
	COMMIT(userPasswd, new UsernamePasswdOption(user, passwd));
}

SessionOptionSet::SessionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void SessionOptionSet::request()
{
	enforceMode(M_REQ);
	COMMIT(mandatoryOpt, new SessionRequestOption());
}

void SessionOptionSet::tearDown()
{
	enforceMode(M_REQ);
	if (mandatoryOpt == nullptr)
		throw logic_error("Request must be part of session");
	COMMIT(teardownOpt, new SessionTeardownOption());
}

void SessionOptionSet::setID(const std::vector<uint8_t> &ticket)
{
	enforceMode(M_REQ, M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionIDOption(ticket));
}

void SessionOptionSet::signalOK()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionOKOption());
}

void SessionOptionSet::signalReject()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionInvalidOption());
}

void SessionOptionSet::setUntrusted()
{
	enforceMode(M_REQ);
	if (reinterpret_cast<SessionIDOption *>(mandatoryOpt.get()) == nullptr)
		throw logic_error("Must advertise a session ID");
	COMMIT(untrustedOpt, new SessionUntrustedOption());
}

IdempotenceOptionSet::IdempotenceOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void IdempotenceOptionSet::requestWindow(uint32_t size)
{
	enforceMode(M_REQ);
	COMMIT(requestOpt, new TokenWindowRequestOption(size));
}

void IdempotenceOptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	COMMIT(expenditureOpt, new TokenExpenditureRequestOption(token));
}

void IdempotenceOptionSet::advertiseWindow(uint32_t base, uint32_t size)
{
	enforceMode(M_AUTH_REP);
	COMMIT(windowOpt, new TokenWindowAdvertOption(base, size));
}

void IdempotenceOptionSet::setReply(SOCKS6TokenExpenditureCode code)
{
	enforceMode(M_AUTH_REP);
	COMMIT(replyOpt, new TokenExpenditureReplyOption(code));
}

}
