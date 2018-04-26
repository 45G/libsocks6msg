#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <boost/shared_ptr.hpp>
#include "socks6msg_base.hh"
#include "socks6msg_option.hh"

namespace S6M
{

class OptionSet
{
	bool tfo;
	bool mptcp;
	
	struct Scheds
	{
		SOCKS6MPTCPScheduler clientProxy;
		SOCKS6MPTCPScheduler proxyServer;
		
		Scheds()
			: clientProxy((SOCKS6MPTCPScheduler) 0), proxyServer((SOCKS6MPTCPScheduler) 0) {}
		
	} mptcpSched;
	
	struct Idem
	{
		bool request;
		bool spend;
		uint32_t token;
		
		bool advertise;
		uint32_t base;
		uint32_t windowSize;
		
		bool reply;
		SOCKS6TokenExpenditureCode replyCode;
		
		Idem()
			: request(false), spend(false), token(0), advertise(false), base(0), windowSize(0), reply(false), replyCode(SOCKS6_TOK_EXPEND_SUCCESS) {}
	} idempotence;
	
	std::set<SOCKS6Method> knownMethods;
	
	struct UsrPswd
	{
		bool attempt;
		
		std::string username;
		std::string passwd;
		
		UsrPswd()
			: attempt(false) {}
	} userPasswdAuth;
	
	std::map<SOCKS6Method, std::vector<uint8_t> > extraAuthData;
	
	std::list<boost::shared_ptr<Option> > extraOptions;
	
	std::list<boost::shared_ptr<Option> > generateOptions();
	
public:
	OptionSet();
	
	~OptionSet();
	
	static OptionSet *parse(ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
	
	bool hasTFO() const
	{
		return tfo;
	}
	
	void setTFO()
	{
		tfo = true;
	}
	
	bool hasMPTCP() const
	{
		return mptcp;
	}
	void setMPTCP()
	{
		mptcp = true;
	}
	
	SOCKS6MPTCPScheduler getClientProxySched() const
	{
		return mptcpSched.clientProxy;
	}
	
	void setClientProxySched(SOCKS6MPTCPScheduler sched);
	
	SOCKS6MPTCPScheduler getProxyServerSched() const
	{
		return mptcpSched.proxyServer;
	}
	
	void setProxyServerSched(SOCKS6MPTCPScheduler sched);
	
	bool requestedTokenWindow() const
	{
		return idempotence.request;
	}
	
	void requestTokenWindow()
	{
		idempotence.request = true;
	}
	
	bool advetisedTokenWindow()
	{
		return idempotence.advertise;
	}
	
	uint32_t getTokenWindowBase() const
	{
		return idempotence.base;
	}
	
	uint32_t getTokenWindowSize() const
	{
		return idempotence.windowSize;
	}
	
	void advetiseTokenWindow(uint32_t base, uint32_t size);
	
	std::set<SOCKS6Method> getKnownMethods() const
	{
		return knownMethods;
	}
	
	void advertiseMethod(SOCKS6Method method)
	{
		knownMethods.insert(method);
	}
	
	bool attemptedUserPasswdAuth() const
	{
		return userPasswdAuth.attempt;
	}
	
	std::string getUsername() const
	{
		return userPasswdAuth.username;
	}
	
	std::string getPassword() const
	{
		return userPasswdAuth.passwd;
	}
	
	void setAuthData(SOCKS6Method method, std::vector<uint8_t> data)
	{
		if (method == SOCKS6_METHOD_USRPASSWD)
		{
			//TODO
		}
		
		//TODO
	}
	
	std::vector<uint8_t> getAuthData()
	{
		if (method == SOCKS6_METHOD_USRPASSWD && userPasswdAuth.attempt)
		{
			//TODO
		}
		
		//TODO
	}
	
	void addOption(SOCKS6OptionKind kind, std::vector<uint8_t> data)
	{
		RawOption rawOption(kind, data.data(), data.size());
		size_t rawLen = rawOption.getLen();
		uint8_t buf[rawLen];
		ByteBuffer bb(buf, rawLen);
		
		shared_ptr<Option> opt(Option::parse(bb));
		opt->apply(this);
	}
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
