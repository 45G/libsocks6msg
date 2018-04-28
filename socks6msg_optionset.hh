#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <boost/shared_ptr.hpp>
#include "socks6msg_bytebuffer.hh"
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
		
		uint32_t base;
		uint32_t windowSize;
		
		SOCKS6TokenExpenditureCode replyCode;
		
		Idem()
			: request(false), spend(false), token(0), base(0), windowSize(0), replyCode((SOCKS6TokenExpenditureCode)0) {}
	} idempotence;
	
	std::set<SOCKS6Method> knownMethods;
	
	struct
	{
		std::string username;
		std::string passwd;
	} userPasswdAuth;
	
	std::map<SOCKS6Method, std::vector<uint8_t> > extraAuthData;
	
	std::list<boost::shared_ptr<Option> > extraOptions;
	
	std::list<boost::shared_ptr<Option> > generateOptions();
	
public:
	OptionSet()
		: tfo(false), mptcp(false) {}
	
	OptionSet (ByteBuffer *bb);
	
	void pack(ByteBuffer *bb);
	
	size_t packedSize();
	
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
	
	void setBothScheds(SOCKS6MPTCPScheduler sched);
	
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
		return idempotence.windowSize > 0;
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
	
	void spendToken(uint32_t token);
	
	bool expenditureAttempted() const
	{
		return idempotence.spend;
	}
	
	uint32_t getToken() const
	{
		return idempotence.token;
	}
	
	void replyToExpenditure(SOCKS6TokenExpenditureCode code);
	
	SOCKS6TokenExpenditureCode getExpenditureReplyCode() const
	{
		return idempotence.replyCode;
	}
	
	std::set<SOCKS6Method> getKnownMethods() const
	{
		return knownMethods;
	}
	
	void advertiseMethod(SOCKS6Method method)
	{
		knownMethods.insert(method);
	}
	
	void attemptUserPasswdAuth(const std::string &user, const std::string &passwd);
	
	std::string getUsername() const
	{
		return userPasswdAuth.username;
	}
	
	std::string getPassword() const
	{
		return userPasswdAuth.passwd;
	}
	
	void setAuthData(SOCKS6Method method, std::vector<uint8_t> data, bool parse = true);
	
	std::map<SOCKS6Method, std::vector<uint8_t> > getExtraAuthData() const
	{
		return extraAuthData;
	}
	
	void addOption(SOCKS6OptionKind kind, const std::vector<uint8_t> &data, bool parse = true);
	
	std::list<boost::shared_ptr<Option> > getExtraOptions() const
	{
		return extraOptions;
	}
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
