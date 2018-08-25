#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <netinet/ip6.h>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <boost/shared_ptr.hpp>
#include "socks6.h"
#include "socks6msg_bytebuffer.hh"

namespace S6M
{

class OptionSet
{
public:
	enum Mode
	{
		M_REQ,
		M_AUTH_REP,
		M_OP_REP,
	};
	
private:
	Mode mode;
	
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
		uint32_t request;
		
		bool spend;
		uint32_t token;
		
		uint32_t base;
		uint32_t windowSize;
		
		SOCKS6TokenExpenditureCode replyCode;
		
		Idem()
			: request(0), spend(false), token(0), base(0), windowSize(0), replyCode((SOCKS6TokenExpenditureCode)0) {}
	} idempotence;
	
	std::set<SOCKS6Method> advertisedMethods;
	
	struct
	{
		boost::shared_ptr<std::string> username;
		boost::shared_ptr<std::string> passwd;
	} userPasswdAuth;

	std::vector<in6_addr> forwardSegments;
	std::vector<in6_addr> returnSegments;
	
	void enforceMode(Mode mode1);
	
	void enforceMode(Mode mode1, Mode mode2);
	
	void enforceMode(Mode mode1, Mode mode2, Mode mode3)
	{
		(void)mode1; (void)mode2; (void)mode3;
	}
	
public:
	OptionSet(Mode mode)
		: mode(mode), tfo(false), mptcp(false) {}
	
	OptionSet(ByteBuffer *bb, Mode mode);
	
	void pack(ByteBuffer *bb) const;
	
	size_t packedSize();
	
	Mode getMode() const
	{
		return mode;
	}
	
	bool getTFO() const
	{
		return tfo;
	}
	
	void setTFO();
	
	bool getMPTCP() const
	{
		return mptcp;
	}
	
	void setMPTCP();
	
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
	
	void setBothScheds(SOCKS6MPTCPScheduler sched);
	
	//TODO: rename most of below methods
	uint32_t requestedTokenWindow() const
	{
		return idempotence.request;
	}
	
	void requestTokenWindow(uint32_t winSize);
	
	uint32_t getTokenWindowBase() const
	{
		return idempotence.base;
	}
	
	uint32_t getTokenWindowSize() const
	{
		return idempotence.windowSize;
	}
	
	void setTokenWindow(uint32_t base, uint32_t size);
	
	void setToken(uint32_t token);
	
	bool hasToken() const
	{
		return idempotence.spend;
	}
	
	uint32_t getToken() const
	{
		return idempotence.token;
	}
	
	void setExpenditureReply(SOCKS6TokenExpenditureCode code);
	
	SOCKS6TokenExpenditureCode getExpenditureReply() const
	{
		return idempotence.replyCode;
	}
	
	const std::set<SOCKS6Method> *getAdvertisedMethods() const
	{
		return &advertisedMethods;
	}
	
	void advertiseMethod(SOCKS6Method method)
	{
		enforceMode(M_REQ);
		
		if (method == SOCKS6_METHOD_UNACCEPTABLE)
			throw InvalidFieldException();
		
		advertisedMethods.insert(method);
	}
	
	void setUsernamePassword(const boost::shared_ptr<std::string> user, const boost::shared_ptr<std::string> passwd);
	
	const boost::shared_ptr<std::string> getUsername() const
	{
		return userPasswdAuth.username;
	}
	
	const boost::shared_ptr<std::string> getPassword() const
	{
		return userPasswdAuth.passwd;
	}

	void setForwardSegments(const std::vector<in6_addr> &segments);

	const std::vector<in6_addr> *getForwardSegments()
	{
		return &forwardSegments;
	}

	void setReturnSegments(const std::vector<in6_addr> &segments);

	const std::vector<in6_addr> *getReturnSegments()
	{
		return &returnSegments;
	}
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
