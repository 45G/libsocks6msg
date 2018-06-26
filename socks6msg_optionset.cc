#include <boost/foreach.hpp>
#include "socks6msg_optionset.hh"
#include "socks6msg_option.hh"

using namespace std;
using namespace boost;

namespace S6M
{

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
	: mode(mode), tfo(false), mptcp(false)
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
			Option::parse(opt, this);
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
		if (mptcpSched.proxyServer == mptcpSched.clientProxy)
		{
			MPSchedOption(SOCKS6_SOCKOPT_LEG_BOTH, mptcpSched.clientProxy).pack(bb);
			optsHead->optionCount++;
			goto both_sched_done;
		}
		else
		{
			MPSchedOption(SOCKS6_SOCKOPT_LEG_CLIENT_PROXY, mptcpSched.clientProxy).pack(bb);
			optsHead->optionCount++;
		}
	}
	if (mptcpSched.proxyServer > 0)
	{
		MPSchedOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, mptcpSched.proxyServer).pack(bb);
		optsHead->optionCount++;
	}
	
both_sched_done:
	if (idempotence.request)
	{
		TokenWindowRequestOption().pack(bb);
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
	
	set<SOCKS6Method> extraMethods(knownMethods);
	extraMethods.erase(SOCKS6_METHOD_NOAUTH);
	if (!extraMethods.empty())
	{
		AuthMethodOption(extraMethods).pack(bb);
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
		if (mptcpSched.proxyServer == mptcpSched.clientProxy)
		{
			size += MPSchedOption(SOCKS6_SOCKOPT_LEG_BOTH, mptcpSched.clientProxy).packedSize();
			goto both_sched_done;
		}
		else
		{
			size += MPSchedOption(SOCKS6_SOCKOPT_LEG_CLIENT_PROXY, mptcpSched.clientProxy).packedSize();
		}
	}
	if (mptcpSched.proxyServer > 0)
		size += MPSchedOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, mptcpSched.proxyServer).packedSize();
	
both_sched_done:
	if (idempotence.request)
		size += TokenWindowRequestOption().packedSize();
	if (idempotence.spend)
		size += TokenExpenditureRequestOption(idempotence.token).packedSize();
	if (idempotence.windowSize > 0)
		size += TokenWindowAdvertOption(idempotence.base, idempotence.windowSize).packedSize();
	if (idempotence.replyCode > 0)
		size += TokenExpenditureReplyOption(idempotence.replyCode).packedSize();
	
	set<SOCKS6Method> extraMethods(knownMethods);
	if (!extraMethods.empty())
		size += AuthMethodOption(extraMethods).packedSize();
	
	if (!userPasswdAuth.username->empty())
		size += UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd).packedSize();
	
	return size;
}

void OptionSet::setTFO()
{
	enforceMode(M_REQ, M_OP_REP);
	
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
	
	if (mptcpSched.clientProxy != (SOCKS6MPTCPScheduler)0 && mptcpSched.clientProxy != sched)
		throw InvalidFieldException();
	
	mptcpSched.clientProxy = sched;
}

void OptionSet::setProxyServerSched(SOCKS6MPTCPScheduler sched)
{
	enforceMode(M_REQ, M_OP_REP);
	
	if (mptcpSched.proxyServer != (SOCKS6MPTCPScheduler)0 && mptcpSched.proxyServer != sched)
		throw InvalidFieldException();
	
	mptcpSched.proxyServer = sched;
}

void OptionSet::setBothScheds(SOCKS6MPTCPScheduler sched)
{
	enforceMode(M_REQ, M_OP_REP);
	
	bool canSetCP = mptcpSched.clientProxy == (SOCKS6MPTCPScheduler)0 || mptcpSched.clientProxy == sched;
	bool canSetPS = mptcpSched.proxyServer == (SOCKS6MPTCPScheduler)0 || mptcpSched.proxyServer == sched;
	
	if (!(canSetCP && canSetPS))
		throw InvalidFieldException();
	
	mptcpSched.clientProxy = sched;
	mptcpSched.proxyServer = sched;
}

void OptionSet::requestTokenWindow()
{
	enforceMode(M_REQ);
	
	idempotence.request = true;
}

void OptionSet::advetiseTokenWindow(uint32_t base, uint32_t size)
{
	enforceMode(M_AUTH_REP, M_OP_REP);
	
	if (size == 0)
		throw InvalidFieldException();
	if (idempotence.windowSize > 0 && (idempotence.base != base || idempotence.windowSize != size))
		throw InvalidFieldException();
	
	idempotence.base = base;
	idempotence.windowSize = size;
}

void OptionSet::spendToken(uint32_t token)
{
	enforceMode(M_REQ);
	
	if (idempotence.spend && idempotence.token != token)
		throw InvalidFieldException();
	
	idempotence.spend = true;
	idempotence.token = token;
}

void OptionSet::replyToExpenditure(SOCKS6TokenExpenditureCode code)
{
	enforceMode(M_OP_REP);
	
	if (code == 0)
		throw InvalidFieldException();
	
	if (idempotence.replyCode != 0 && idempotence.replyCode != code)
		throw InvalidFieldException();
	
	idempotence.replyCode = code;
}

void OptionSet::attemptUserPasswdAuth(const boost::shared_ptr<string> user, const boost::shared_ptr<string> passwd)
{
	enforceMode(M_REQ);
	
	if (user->size() == 0 || passwd->size() == 0)
		throw InvalidFieldException();
	
	if (userPasswdAuth.username->size() != 0 && (*user != *userPasswdAuth.username || *passwd != *userPasswdAuth.passwd))
		throw InvalidFieldException();
	
	userPasswdAuth.username = user;
	userPasswdAuth.passwd = passwd;
}

}
