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
	std::unique_ptr<Option>                 mandatoryOpt; //Request or ID or OK or Invalid
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
	std::unique_ptr<Option>                        replyOpt;
	
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
	
	void setReply(bool accepted);
	
	boost::optional<bool> getReply() const
	{
		if (reinterpret_cast<const TokenExpenditureAcceptedOption *>(replyOpt.get()) != nullptr)
			return true;
		if (reinterpret_cast<const TokenExpenditureRejectedOption *>(replyOpt.get()) != nullptr)
			return false;
		return {};
	}
};

template <typename OPT>
class StackOptionPair: public OptionSetBase
{
	std::shared_ptr<OPT> clientProxy;
	std::shared_ptr<OPT> proxyRemote;
	
public:
	typedef OPT Option;
	
	StackOptionPair(OptionSet *owner);
	
	void set(SOCKS6StackLeg leg, typename OPT::Value value);
	
	boost::optional<typename OPT::Value> get(SOCKS6StackLeg leg) const;
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	void set(typename OPT::Value value)
	{
		static_assert (LEG != SOCKS6_STACK_LEG_BOTH, "Option is not restricted to one leg");
		set(LEG, value);
	}
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	boost::optional<typename OPT::Value> get() const
	{
		static_assert (LEG != SOCKS6_STACK_LEG_BOTH, "Option is not restricted to one leg");
		return get(OPT::LEG_RESTRICT);
	}
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

class UserPasswdOptionSet: public OptionSetBase
{
	std::unique_ptr<UsernamePasswdReqOption>   req;
	std::unique_ptr<UsernamePasswdReplyOption> reply;
public:
	UserPasswdOptionSet(OptionSet *owner);
	
	void setCredentials(const std::string &user, const std::string &passwd);
	
	const std::string *getUsername() const
	{
		if (req == nullptr)
			return nullptr;
		return req->getUsername();
	}
	
	const std::string *getPassword() const
	{
		if (req == nullptr)
			return nullptr;
		return req->getPassword();
	}
	
	void setReply(bool success);
	
	boost::optional<bool> getReply()
	{
		if (reply == nullptr)
			return {};
		return reply->isSuccessful();
	}
};

class AuthMethodOptionSet: public OptionSetBase
{
	std::unique_ptr<AuthMethodAdvertOption> advertOption;
	std::unique_ptr<AuthMethodSelectOption> selectOption;
	
public:
	AuthMethodOptionSet(OptionSet *owner);
	
	const std::set<SOCKS6Method> *getAdvertised() const
	{
		static const std::set<SOCKS6Method> EMPTY_SET;
		if (advertOption == nullptr)
			return &EMPTY_SET;
		
		return advertOption->getMethods();
	}
	
	void advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen);

	uint16_t getInitialDataLen() const
	{
		if (advertOption == nullptr)
			return 0;
		return advertOption->getInitialDataLen();
	}
	
	void select(SOCKS6Method method);
	
	boost::optional<SOCKS6Method> getSelected() const
	{
		if (selectOption == nullptr)
			return {};
		return selectOption->getMethod();
	}
};

class OptionSet: public OptionSetBase
{
	std::list<Option *> options;
	size_t optionsSize = 0;
	
	void registerOption(Option *option)
	{
		if (packedSize() + option->packedSize() > SOCKS6_OPTIONS_LENGTH_MAX)
			throw std::length_error("Option would not fit");
		options.push_back(option);
		optionsSize += option->packedSize();
	}
	
public:
	StackOptionSet       stack       { this };
	SessionOptionSet     session     { this };
	IdempotenceOptionSet idempotence { this };
	UserPasswdOptionSet  userPasswd  { this };
	AuthMethodOptionSet  authMethods { this };

	OptionSet(Mode mode)
		: OptionSetBase(this, mode) {}
	
	OptionSet(ByteBuffer *bb, Mode mode, uint16_t optionsLength);
	
	void pack(ByteBuffer *bb) const;
	
	size_t packedSize() const
	{
		return optionsSize;
	}
	
	Mode getMode() const
	{
		return mode;
	}
	
	friend class SessionOptionSet;
	friend class IdempotenceOptionSet;
	friend class StackOptionSet;
	template <typename T>
	friend class StackOptionPair;
	friend class UserPasswdOptionSet;
	friend class AuthMethodOptionSet;
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
