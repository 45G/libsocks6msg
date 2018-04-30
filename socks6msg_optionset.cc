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
		opts.push_back(shared_ptr<Option>(new TFOOption()));
	if (mptcp)
		opts.push_back(shared_ptr<Option>(new MPTCPOption()));
	
	if (mptcpSched.clientProxy > 0)
	{
		if (mptcpSched.proxyServer == mptcpSched.clientProxy)
		{
			opts.push_back(shared_ptr<Option>(new MPScehdOption(SOCKS6_SOCKOPT_LEG_BOTH, mptcpSched.clientProxy)));
			goto both_sched_done;
		}
		else
		{
			opts.push_back(shared_ptr<Option>(new MPScehdOption(SOCKS6_SOCKOPT_LEG_CLIENT_PROXY, mptcpSched.clientProxy)));
		}
	}
	if (mptcpSched.proxyServer > 0)
		opts.push_back(shared_ptr<Option>(new MPScehdOption(SOCKS6_SOCKOPT_LEG_PROXY_SERVER, mptcpSched.proxyServer)));
	
both_sched_done:
	if (idempotence.request)
		opts.push_back(shared_ptr<Option>(new TokenWindowRequestOption()));
	if (idempotence.spend)
		opts.push_back(shared_ptr<Option>(new TokenExpenditureRequestOption(idempotence.token)));
	if (idempotence.windowSize > 0)
		opts.push_back(shared_ptr<Option>(new TokenWindowAdvertOption(idempotence.base, idempotence.windowSize)));
	if (idempotence.replyCode > 0)
		opts.push_back(shared_ptr<Option>(new TokenExpenditureReplyOption(idempotence.replyCode)));
	
	set<SOCKS6Method> extraMethods(knownMethods);
	extraMethods.erase(SOCKS6_METHOD_NOAUTH);
	if (userPasswdAuth.username.length() > 0)
		extraMethods.erase(SOCKS6_METHOD_USRPASSWD);
	if (!extraMethods.empty())
		opts.push_back(shared_ptr<Option>(new AuthMethodOption(extraMethods)));
	
	if (!userPasswdAuth.username.empty())
		opts.push_back(shared_ptr<Option>(new UsernamePasswdOption(userPasswdAuth.username, userPasswdAuth.passwd)));
	
	BOOST_FOREACH(shared_ptr<Option> opt, extraOptions)
	{
		opts.push_back(opt);
	}
	
	return opts;
}

OptionSet::OptionSet(ByteBuffer *bb)
{
	list<shared_ptr<Option> > opts;
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
			opts.push_back(shared_ptr<Option>(Option::parse(opt)));
		}
		catch (InvalidFieldException) {}
	}
		
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		try
		{
			opt->apply(this);
		}
		catch (InvalidFieldException)
		{
			extraOptions.push_back(opt);
		}
	}
}

void OptionSet::pack(ByteBuffer *bb)
{
	list<shared_ptr<Option> > opts = generateOptions();
	
	SOCKS6Options *optsHead = bb->get<SOCKS6Options>();
	
	if (opts.size() > 255)
		throw InvalidFieldException();
	
	optsHead->optionCount = opts.size();
	
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		opt->pack(bb);
	}
}

size_t OptionSet::packedSize()
{
	list<shared_ptr<Option> > opts = generateOptions();
	if (opts.size() > 255)
		throw InvalidFieldException();
	
	size_t size = sizeof(SOCKS6Options);
	
	BOOST_FOREACH(shared_ptr<Option> opt, opts)
	{
		size += opt->packedSize();
	}
	
	return size;
}

void OptionSet::setClientProxySched(SOCKS6MPTCPScheduler sched)
{
	if (mptcpSched.clientProxy != (SOCKS6MPTCPScheduler)0 && mptcpSched.clientProxy != sched)
		throw InvalidFieldException();
	
	mptcpSched.clientProxy = sched;
}

void OptionSet::setBothScheds(SOCKS6MPTCPScheduler sched)
{
	bool canSetCP = mptcpSched.clientProxy == (SOCKS6MPTCPScheduler)0 || mptcpSched.clientProxy == sched;
	bool canSetPS = mptcpSched.proxyServer == (SOCKS6MPTCPScheduler)0 || mptcpSched.proxyServer == sched;
	
	if (!(canSetCP && canSetPS))
		throw InvalidFieldException();
	
	mptcpSched.clientProxy = sched;
	mptcpSched.proxyServer = sched;
}

void OptionSet::setProxyServerSched(SOCKS6MPTCPScheduler sched)
{
	if (mptcpSched.proxyServer != (SOCKS6MPTCPScheduler)0 && mptcpSched.proxyServer != sched)
		throw InvalidFieldException();
	
	mptcpSched.proxyServer = sched;
}

void OptionSet::advetiseTokenWindow(uint32_t base, uint32_t size)
{
	if (size == 0)
		throw InvalidFieldException();
	if (idempotence.windowSize > 0 && (idempotence.base != base || idempotence.windowSize != size))
		throw InvalidFieldException();
	
	idempotence.base = base;
	idempotence.windowSize = size;
}

void OptionSet::spendToken(uint32_t token)
{
	if (idempotence.spend && idempotence.token != token)
		throw InvalidFieldException();
	
	idempotence.spend = true;
	idempotence.token = token;
}

void OptionSet::replyToExpenditure(SOCKS6TokenExpenditureCode code)
{
	if (idempotence.replyCode != 0 && idempotence.replyCode != code)
		throw InvalidFieldException();
	
	idempotence.replyCode = code;
}

void OptionSet::attemptUserPasswdAuth(const string &user, const string &passwd)
{
	if (user.size() == 0 || passwd.size() == 0)
		throw InvalidFieldException();
	
	if (userPasswdAuth.username.size() != 0 && (user != userPasswdAuth.username || passwd != userPasswdAuth.passwd))
		throw InvalidFieldException();
	
	userPasswdAuth.username = user;
	userPasswdAuth.passwd = passwd;
}

void OptionSet::setAuthData(SOCKS6Method method, std::vector<uint8_t> data, bool parse)
{
	if (!parse)
		goto as_is;
	
	try
	{
		if (method == SOCKS6_METHOD_USRPASSWD)
		{
			ByteBuffer bb(data.data(), data.size());
			UserPasswordRequest req(&bb);
			
			if (bb.getUsed() != data.size())
				throw InvalidFieldException();
			
			attemptUserPasswdAuth(req.getUsername(), req.getPassword());
			
			return;
		}
	}
	catch (InvalidFieldException) {}
	catch (BadVersionException) {}
	catch (EndOfBufferException) {}
	
as_is:
	std::map<SOCKS6Method, vector<uint8_t> >::iterator it = extraAuthData.find(method);
	if (it != extraAuthData.end())
	{
		if (it->second.size() != data.size())
			throw InvalidFieldException();
		if (memcmp(it->second.data(), data.data(), data.size()) != 0)
			throw InvalidFieldException();
	}
	
	extraAuthData[method] = data;
}

void OptionSet::addOption(SOCKS6OptionKind kind, const vector<uint8_t> &data, bool parse)
{
	RawOption rawOption(kind, data.data(), data.size());
	
	if (!parse)
	{
		rawOption.apply(this);
		return;
	}
	
	size_t rawLen = rawOption.packedSize();
	uint8_t buf[rawLen];
	ByteBuffer bb(buf, rawLen);
	
	shared_ptr<Option> opt(Option::parse(&bb));
	opt->apply(this);
}

}
