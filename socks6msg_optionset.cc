#include <boost/foreach.hpp>
#include "socks6msg_optionset.hh"
#include "socks6msg_option.hh"

using namespace std;
using namespace boost;

namespace S6M
{

template <typename T> static bool mayAssign(T field, T value)
{
	return (field == (T)0 || field == value);
}

template <typename T> static bool mayAssign(T field1, T field2, T value)
{
	return mayAssign(field1, value) && mayAssign(field2, value);
}

template <typename T> static void checkedAssignment(T *field, T value)
{
	if (!mayAssign(*field, value))
		throw InvalidFieldException();

	*field = value;
}

template <typename T> static void checkedAssignment(T *field1, T *field2, T value)
{
	if (!mayAssign(*field1, *field2, value))
		throw InvalidFieldException();

	*field1 = value;
	*field2 = value;
}

template <typename T, typename U> static void checkedAssignment(T *field1, T value1, U *field2, U value2)
{
	if (!mayAssign(*field1, value1))
		throw InvalidFieldException();
	if (!mayAssign(*field2, value2))
		throw InvalidFieldException();

	*field1 = value1;
	*field2 = value2;
}


void OptionSet::enforceMode(OptionSet::Mode mode1)
{
	if (mode != mode1)
		throw InvalidFieldException();
}

void OptionSet::enforceMode(OptionSet::Mode mode1, OptionSet::Mode mode2)
{
	if (mode != mode1 && mode != mode2)
		throw InvalidFieldException();
}

OptionSet::OptionSet(ByteBuffer *bb, Mode mode)
	: mode(mode), tfo(false), mptcp(false), backlog(0)
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	for (int i = 0; i < optsHead->optionCount; i++)
	{
		SOCKS6Option *opt = bb->get<SOCKS6Option>();
		
		/* bad option length wrecks everything */
		if (opt->len < 2)
			throw InvalidFieldException();
	
		bb->get<uint8_t>(opt->len - sizeof(SOCKS6Option));
		
		try
		{
			Option::incementalParse(opt, this);
		}
		catch (InvalidFieldException) {}
	}
}

void OptionSet::pack(ByteBuffer *bb) const
{
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	optsHead->optionCount = 0;
	
	if (tfo)
	{
		TFOOption().pack(bb);
		optsHead->optionCount++;
	}
	if (mptcp)
	{
		MPTCPOption().pack(bb);
		optsHead->optionCount++;
	}
	
	if (mptcpSched.clientProxy > 0)
	{
		if (mptcpSched.proxyRemote == mptcpSched.clientProxy)
		{
			MPSchedOption(SOCKS6_STACK_LEG_BOTH, mptcpSched.clientProxy).pack(bb);
			optsHead->optionCount++;
			goto both_sched_done;
		}
		else
		{
			MPSchedOption(SOCKS6_STACK_LEG_CLIENT_PROXY, mptcpSched.clientProxy).pack(bb);
			optsHead->optionCount++;
		}
	}
	if (mptcpSched.proxyRemote > 0)
	{
		MPSchedOption(SOCKS6_STACK_LEG_PROXY_REMOTE, mptcpSched.proxyRemote).pack(bb);
		optsHead->optionCount++;
	}
	
both_sched_done:

	if (ipTOS.clientProxy > 0)
	{
		if (ipTOS.proxyRemote == ipTOS.clientProxy)
		{
			TOSOption(SOCKS6_STACK_LEG_BOTH, ipTOS.clientProxy).pack(bb);
			optsHead->optionCount++;
			goto both_tos_done;
		}
		else
		{
			TOSOption(SOCKS6_STACK_LEG_CLIENT_PROXY, ipTOS.clientProxy).pack(bb);
			optsHead->optionCount++;
		}
	}
	if (ipTOS.proxyRemote > 0)
	{
		TOSOption(SOCKS6_STACK_LEG_PROXY_REMOTE, ipTOS.proxyRemote).pack(bb);
		optsHead->optionCount++;
	}

both_tos_done:

	if (idempotence.request > 0)
	{
		TokenWindowRequestOption(idempotence.request).pack(bb);
		optsHead->optionCount++;
	}
	if (idempotence.spend)
	{
		TokenExpenditureRequestOption(idempotence.token).pack(bb);
		optsHead->optionCount++;
	}
	if (idempotence.windowSize > 0)
	{
		TokenWindowAdvertOption(idempotence.base, idempotence.windowSize).pack(bb);
		optsHead->optionCount++;
	}
	if (idempotence.replyCode > 0)
	{
		TokenExpenditureReplyOption(idempotence.replyCode).pack(bb);
		optsHead->optionCount++;
	}
	
	if (!methods.advertised.empty())
	{
		AuthMethodOption(methods.initialDataLen, methods.advertised).pack(bb);
		optsHead->optionCount++;
	}
	
	if (userPasswdAuth.username.get() != NULL && !userPasswdAuth.username->empty())
	{
		UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd).pack(bb);
		optsHead->optionCount++;
	}
}

size_t OptionSet::packedSize()
{
	size_t size = sizeof(SOCKS6Options);
	
	if (tfo)
		size += TFOOption().packedSize();
	if (mptcp)
		size += MPTCPOption().packedSize();
	
	if (mptcpSched.clientProxy > 0)
	{
		if (mptcpSched.proxyRemote == mptcpSched.clientProxy)
		{
			size += MPSchedOption(SOCKS6_STACK_LEG_BOTH, mptcpSched.clientProxy).packedSize();
			goto both_sched_done;
		}
		else
		{
			size += MPSchedOption(SOCKS6_STACK_LEG_CLIENT_PROXY, mptcpSched.clientProxy).packedSize();
		}
	}
	if (mptcpSched.proxyRemote > 0)
		size += MPSchedOption(SOCKS6_STACK_LEG_PROXY_REMOTE, mptcpSched.proxyRemote).packedSize();
	
both_sched_done:

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

	if (idempotence.request > 0)
		size += TokenWindowRequestOption(idempotence.request).packedSize();
	if (idempotence.spend)
		size += TokenExpenditureRequestOption(idempotence.token).packedSize();
	if (idempotence.windowSize > 0)
		size += TokenWindowAdvertOption(idempotence.base, idempotence.windowSize).packedSize();
	if (idempotence.replyCode > 0)
		size += TokenExpenditureReplyOption(idempotence.replyCode).packedSize();
	
	if (!methods.advertised.empty())
		size += AuthMethodOption(methods.initialDataLen, methods.advertised).packedSize();
	
	if (!userPasswdAuth.username->empty())
		size += UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd).packedSize();
	
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

void OptionSet::setTFO()
{
	enforceMode(M_REQ);
	tfo = true;
}

void OptionSet::setMPTCP()
{
	enforceMode(M_OP_REP);
	mptcp = true;
}

void OptionSet::setClientProxySched(SOCKS6MPTCPScheduler sched)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&mptcpSched.clientProxy, sched);
}

void OptionSet::setProxyRemoteSched(SOCKS6MPTCPScheduler sched)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&mptcpSched.proxyRemote, sched);
}

void OptionSet::setBothScheds(SOCKS6MPTCPScheduler sched)
{
	enforceMode(M_REQ, M_OP_REP);
	checkedAssignment(&mptcpSched.clientProxy, &mptcpSched.proxyRemote, sched);
}

void OptionSet::setBacklog(uint16_t backlog)
{
	checkedAssignment(&this->backlog, backlog);
}

void OptionSet::requestTokenWindow(uint32_t winSize)
{
	enforceMode(M_REQ);
	checkedAssignment(&idempotence.request, winSize);
}

void OptionSet::setTokenWindow(uint32_t base, uint32_t size)
{
	enforceMode(M_AUTH_REP);
	
	if (size == 0)
		throw InvalidFieldException();
	if (idempotence.windowSize > 0 && (idempotence.base != base || idempotence.windowSize != size))
		throw InvalidFieldException();
	
	idempotence.base = base;
	idempotence.windowSize = size;
}

void OptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	
	if (idempotence.spend && idempotence.token != token)
		throw InvalidFieldException();
	
	idempotence.spend = true;
	idempotence.token = token;
}

void OptionSet::setExpenditureReply(SOCKS6TokenExpenditureCode code)
{
	enforceMode(M_AUTH_REP);
	
	if (code == 0)
		throw InvalidFieldException();
	
	checkedAssignment(&idempotence.replyCode, code);
}

void OptionSet::advertiseMethod(SOCKS6Method method)
{
	enforceMode(M_REQ);

	if (method == SOCKS6_METHOD_NOAUTH)
		return;
	if (method == SOCKS6_METHOD_UNACCEPTABLE)
		throw InvalidFieldException();

	methods.advertised.insert(method);
}

void OptionSet::setInitialDataLen(uint16_t initialDataLen)
{
	enforceMode(M_REQ);

	if (initialDataLen > SOCKS6_INITIAL_DATA_MAX)
		throw InvalidFieldException();

	checkedAssignment(&methods.initialDataLen, initialDataLen);
}

void OptionSet::setUsernamePassword(const boost::shared_ptr<string> user, const boost::shared_ptr<string> passwd)
{
	enforceMode(M_REQ);
	
	if (user->size() == 0 || passwd->size() == 0)
		throw InvalidFieldException();
	
	if (userPasswdAuth.username.get() != NULL && (*user != *userPasswdAuth.username || *passwd != *userPasswdAuth.passwd))
		throw InvalidFieldException();
	
	userPasswdAuth.username = user;
	userPasswdAuth.passwd = passwd;
}

}
