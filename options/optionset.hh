#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <memory>
#include <boost/optional/optional.hpp>
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
	
	bool requested() const
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
	
	bool isOK() const
	{
		return dynamic_cast<SessionOKOption *>(mandatoryOpt.get()) != nullptr;
	}
	
	void signalReject();
	
	bool rejected() const
	{
		return dynamic_cast<SessionInvalidOption *>(mandatoryOpt.get()) != nullptr;
	}
	
	void setUntrusted();
	
	bool isUntrusted() const
	{
		return untrustedOpt != nullptr;
	}
};

class IdempotenceOptionSet: public OptionSetBase
{
	std::unique_ptr<TokenWindowRequestOption>      requestOpt;
	std::unique_ptr<TokenExpenditureRequestOption> expenditureOpt;
	std::unique_ptr<TokenWindowAdvertOption>       windowOpt;
	std::unique_ptr<TokenExpenditureReplyOption>   replyOpt;
	
public:
	IdempotenceOptionSet(OptionSet *owner);
	
	void request(uint32_t size);
	
	uint32_t requestedSize() const
	{
		if (requestOpt == nullptr)
			return 0;
		return requestOpt->getWinSize();
	}
	
	void setToken(uint32_t token);
	
	boost::optional<uint32_t> getToken() const
	{
		if (expenditureOpt == nullptr)
			return {};
		return expenditureOpt->getToken();
	}
	
	void advertise(uint32_t base, uint32_t size);
	
	boost::optional<uint32_t> advertisedBase() const
	{
		if (windowOpt == nullptr)
			return {};
		return windowOpt->getWinBase();
	}
	
	uint32_t advertisedSize() const
	{
		if (windowOpt == nullptr)
			return 0;
		return windowOpt->getWinSize();
	}
	
	void setReply(SOCKS6TokenExpenditureCode code);
	
	boost::optional<SOCKS6TokenExpenditureCode> getReply() const
	{
		if (replyOpt == nullptr)
			return {};
		return replyOpt->getCode();
	}
};

template <typename T>
class StackOptionPair: public OptionSetBase
{
	std::shared_ptr<T> clientProxy;
	std::shared_ptr<T> proxyRemote;
	
public:
	typedef T Option;
	
	StackOptionPair(OptionSet *owner);
	
	void set(SOCKS6StackLeg leg, typename T::Value value);
	
	boost::optional<typename T::Value> get(SOCKS6StackLeg leg) const;
};

class StackOptionSet: public OptionSetBase
{
public:
	StackOptionPair<TOSOption>     tos     { owner };
	StackOptionPair<TFOOption>     tfo     { owner };
	StackOptionPair<MPOption>      mp      { owner };
	StackOptionPair<BacklogOption> backlog { owner };
	
	StackOptionSet(OptionSet *owner);
};

class OptionSet: public OptionSetBase
{
	std::unique_ptr<AuthMethodOption> authMethodOption;
	
	std::unique_ptr<UsernamePasswdOption> userPasswd;
	
	std::list<Option *> options;
	size_t optionsSize = 0;
	
	void registerOption(Option *option)
	{
		options.push_back(option);
		optionsSize += option->packedSize();
	}
	
public:
	StackOptionSet       stack       { this };
	SessionOptionSet     session     { this };
	IdempotenceOptionSet idempotence { this };

	OptionSet(Mode mode)
		: OptionSetBase(this, mode) {}
	
	OptionSet(ByteBuffer *bb, Mode mode);
	
	void pack(ByteBuffer *bb) const;
	
	size_t packedSize() const;
	
	Mode getMode() const
	{
		return mode;
	}
	
	const std::set<SOCKS6Method> *getAdvertisedMethods() const
	{
		static const std::set<SOCKS6Method> EMPTY_SET;
		if (authMethodOption == nullptr)
			return &EMPTY_SET;
		
		return authMethodOption->getMethods();
	}
	
	void advertiseMethods(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen);

	uint16_t getInitialDataLen() const
	{
		if (authMethodOption == nullptr)
			return 0;
		return authMethodOption->getInitialDataLen();
	}
	
	void setUsernamePassword(const std::string &user, const std::string &passwd);
	
	const std::string *getUsername() const
	{
		if (userPasswd == nullptr)
			return nullptr;
		return userPasswd->getUsername();
	}
	
	const std::string *getPassword() const
	{
		if (userPasswd == nullptr)
			return nullptr;
		return userPasswd->getPassword();
	}
	
	friend class SessionOptionSet;
	friend class IdempotenceOptionSet;
	friend class StackOptionSet;
	template <typename T>
	friend class StackOptionPair;
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
