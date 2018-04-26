#include <memory>
#include <boost/foreach.hpp>
#include "socks6msg_optionset.hh"

using namespace std;
using namespace boost;

namespace S6M
{

list<shared_ptr<Option> > OptionSet::generateOptions()
{
	list<shared_ptr<Option> > opts;
	
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
	
	set<SOCKS6Method> extraMethods(knownMethods);
	extraMethods.erase(SOCKS6_METHOD_NOAUTH);
	if (userPasswdAuth.attempt)
		extraMethods.erase(SOCKS6_METHOD_USRPASSWD);
	if (!extraMethods.empty())
		opts.push_back(new AuthMethodOption(extraMethods));
	
	if (!userPasswdAuth.username.empty())
		opts.push_back(new UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd));
	
	BOOST_FOREACH(shared_ptr<Option> opt, extraOptions)
	{
		opts.push_back(opt);
	}
	
	return opts;
}

OptionSet::OptionSet()
	: tfo(false), mptcp(false) {}

OptionSet::~OptionSet() {}

OptionSet *OptionSet::parse(ByteBuffer *bb)
{
	list<shared_ptr<Option> > opts;
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	for (int i = 0; i < optsHead->optionCount; i++)
	{
		SOCKS6Option *opt = bb->get<SOCKS6Option>();
		
		/* bad option length wrecks everything */
		if (opt->len < 2)
			throw Exception(S6M_ERR_INVALID);
	
		bb->get<uint8_t>(opt->len - sizeof(SOCKS6Option));
		
		try
		{
			opts.push_back(shared_ptr<Option>(Option::parse(opt)));
		}
		catch (Exception ex)
		{
			/* silently ignote bad options */
			if (ex.getError() == S6M_ERR_INVALID)
				continue;
			throw ex;
		}
	}
	
	OptionSet *optSet = new OptionSet();
	
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		try
		{
			opt->apply(optSet);
		}
		catch (Exception ex)
		{
			/* silently ignote bad options */
			if (ex.getError() == S6M_ERR_INVALID)
				continue;
			
			delete optSet;
			throw ex;
		}
	}
	
	return optSet;
}

void OptionSet::pack(ByteBuffer *bb)
{
	list<shared_ptr<Option> > opts = generateOptions();
	
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	if (opts.size() > 255)
		throw Exception(S6M_ERR_INVALID);
	
	optsHead->optionCount = opts.size();
	
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		opt->pack(bb);
	}
}

void OptionSet::setClientProxySched(SOCKS6MPTCPScheduler sched)
{
	if (mptcpSched.clientProxy != (SOCKS6MPTCPScheduler)0 && mptcpSched.clientProxy != sched)
		throw Exception(S6M_ERR_INVALID);
	
	mptcpSched.clientProxy = sched;
}

void OptionSet::setProxyServerSched(SOCKS6MPTCPScheduler sched)
{
	if (mptcpSched.proxyServer != (SOCKS6MPTCPScheduler)0 && mptcpSched.proxyServer != sched)
		throw Exception(S6M_ERR_INVALID);
	
	mptcpSched.proxyServer = sched;
}

void OptionSet::advetiseTokenWindow(uint32_t base, uint32_t size)
{
	if (idempotence.advertise && (idempotence.base != base || idempotence.windowSize != size))
		throw Exception(S6M_ERR_INVALID);
	
	idempotence.advertise = true;
	idempotence.base = base;
	idempotence.windowSize = size;
}

void OptionSet::addOption(SOCKS6OptionKind kind, vector<uint8_t> data)
{
	RawOption rawOption(kind, data.data(), data.size());
	size_t rawLen = rawOption.getLen();
	uint8_t buf[rawLen];
	ByteBuffer bb(buf, rawLen);
	
	shared_ptr<Option> opt(Option::parse(bb));
	opt->apply(this);
}

}
