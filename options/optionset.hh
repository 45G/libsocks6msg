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

//TODO: this is waaaaaay too bloated

class OptionSet;

class OptionSetBase
{
public:
	enum Mode
	{
		M_REQ,
		M_AUTH_REP,
		M_OP_REP,
	};
	
protected:
	OptionSet *owner;
	Mode mode;
	
	void enforceMode(Mode mode1) const;
	
	void enforceMode(Mode mode1, Mode mode2) const;
	
	template <typename T>
	void ensureVacant(const std::unique_ptr<T> &ptr)
	{
		if (ptr.get() != nullptr)
			throw std::logic_error("Option already in place");
	}
	
public:
	OptionSetBase(OptionSet *owner, Mode mode)
		: owner(owner), mode(mode) {}
};

class SessionOptionSet: public OptionSetBase
{
	std::unique_ptr<SessionOption>          mandatoryOpt;
	std::unique_ptr<SessionTeardownOption>  teardownOpt;
	std::unique_ptr<SessionUntrustedOption> untrustedOpt;
	
public:
	SessionOptionSet(OptionSet *owner);
	
	void request();
	
	bool requested()
	{
		return dynamic_cast<SessionRequestOption *>(mandatoryOpt.get()) != nullptr;
	}
	
	void tearDown();
	
	bool tornDown() const
	{
		return teardownOpt != nullptr;
	}
	
	void setID(const std::vector<uint8_t> &ticket);
	
	const std::vector<uint8_t> *getID() const
	{
		enforceMode(M_REQ, M_AUTH_REP);
		
		SessionIDOption *opt = dynamic_cast<SessionIDOption *>(mandatoryOpt.get());
		if (opt == nullptr)
			return nullptr;
		return opt->getTicket();
	}
	
	void signalOK();
	
	bool isOK()
	{
		return dynamic_cast<SessionOKOption *>(mandatoryOpt.get()) != nullptr;
	}
	
	void signalReject();
	
	bool rejected() const
	{
		return dynamic_cast<SessionInvalidOption *>(mandatoryOpt.get()) != nullptr;
	}
	
	void setUntrusted();
	
	bool isUntrusted()
	{
		return untrustedOpt != nullptr;
	}
};

class OptionSet: public OptionSetBase
{
	struct TOS
	{
		uint8_t clientProxy;
		uint8_t proxyRemote;

		TOS()
			: clientProxy(0), proxyRemote(0) {}
	} ipTOS;

	bool tfo = false;
	uint16_t tfoPayload = 0;
	
	bool mptcp = false;
	
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
	
	std::unique_ptr<UsernamePasswdOption> userPasswd;
	
	SessionOptionSet sessionSet;
	
	std::list<Option *> options;
	size_t optionsSize = 0;
	
	void registerOption(Option *option)
	{
		options.push_back(option);
		optionsSize += option->packedSize();
	}
	
public:
	OptionSet(Mode mode)
		: OptionSetBase(this, mode), sessionSet(this) {}
	
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
	
	void setUsernamePassword(const std::string &user, const std::string &passwd);
	
	const std::string *getUsername() const
	{
		if (userPasswd.get() == nullptr)
			return nullptr;
		return userPasswd->getUsername();
	}
	
	const std::string *getPassword() const
	{
		if (userPasswd.get() == nullptr)
			return nullptr;
		return userPasswd->getPassword();
	}
	
	SessionOptionSet *session()
	{
		return &sessionSet;
	}
	
	const SessionOptionSet *session() const
	{
		return &sessionSet;
	}
	
	friend class SessionOptionSet;
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
