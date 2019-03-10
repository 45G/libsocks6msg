#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <memory>
#include "option.hh"
#include "stackoption.hh"
#include "idempotenceoption.hh"
#include "authmethodoption.hh"
#include "authdataoption.hh"
#include "sessionoption.hh"

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
	
	struct TOS
	{
		uint8_t clientProxy;
		uint8_t proxyRemote;

		TOS()
			: clientProxy(0), proxyRemote(0) {}
	} ipTOS;

	bool tfo = false;
	uint16_t tfoPayload = 0;
	
	bool mptcp;
	
	struct
	{
		SOCKS6MPTCPScheduler clientProxy = (SOCKS6MPTCPScheduler)0;
		SOCKS6MPTCPScheduler proxyRemote = (SOCKS6MPTCPScheduler)0;
		
	} mptcpSched;

	uint16_t backlog = 0;
	
	struct
	{
		uint32_t request = 0;
		
		bool spend = false;
		uint32_t token = 0;
		
		uint32_t base;
		uint32_t windowSize = 0;
		
		SOCKS6TokenExpenditureCode replyCode = (SOCKS6TokenExpenditureCode)0;
	} idempotence;
	
	struct
	{
		uint16_t initialDataLen = 0;
		std::set<SOCKS6Method> advertised;
	} methods;
	
	struct
	{
		std::shared_ptr<std::string> username;
		std::shared_ptr<std::string> passwd;
	} userPasswdAuth;
	
	std::unique_ptr<SessionOption> sessionOption;
	
	std::list<Option *> options;
	size_t optionsSize = 0;
	
	void enforceMode(Mode mode1);
	
	void enforceMode(Mode mode1, Mode mode2);
	
	void enforceMode(Mode mode1, Mode mode2, Mode mode3)
	{
		(void)mode1; (void)mode2; (void)mode3;
	}
	
public:
	OptionSet(Mode mode)
		: mode(mode) {}
	
	OptionSet(ByteBuffer *bb, Mode mode);
	
	void pack(ByteBuffer *bb) const;
	
	size_t packedSize() const;
	
	Mode getMode() const
	{
		return mode;
	}
	
	void setClientProxyTOS(uint8_t ipTOS);

	uint8_t getClientProxyTOS() const
	{
		return ipTOS.clientProxy;
	}

	void setProxyRemoteTOS(uint8_t ipTOS);

	uint8_t getProxyRemoteTOS() const
	{
		return ipTOS.proxyRemote;
	}

	void setBothTOS(uint8_t ipTOS);

	uint16_t getTFOPayload() const
	{
		return tfoPayload;
	}
	
	void setTFOPayload(uint16_t payloadSize);

	bool hasTFO() const
	{
		return tfo;
	}
	
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
	
	SOCKS6MPTCPScheduler getProxyRemoteSched() const
	{
		return mptcpSched.proxyRemote;
	}
	
	void setProxyRemoteSched(SOCKS6MPTCPScheduler sched);
	
	void setBothScheds(SOCKS6MPTCPScheduler sched);

	void setBacklog(uint16_t backlog);

	uint16_t getBacklog() const
	{
		return backlog;
	}
	
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
		return &methods.advertised;
	}
	
	void advertiseMethod(SOCKS6Method method);

	uint16_t getInitialDataLen() const
	{
		if (methods.advertised.empty())
			return 0;
		return methods.initialDataLen;
	}

	void setInitialDataLen(uint16_t initialDataLen);
	
	void setUsernamePassword(const std::shared_ptr<std::string> user, const std::shared_ptr<std::string> passwd);
	
	const std::shared_ptr<std::string> getUsername() const
	{
		return userPasswdAuth.username;
	}
	
	const std::shared_ptr<std::string> getPassword() const
	{
		return userPasswdAuth.passwd;
	}
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
