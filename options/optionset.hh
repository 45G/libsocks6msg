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
#include "resolutionoption.hh"

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
	
	void setID(const std::vector<uint8_t> &id);
	
	const std::vector<uint8_t> *getID() const
	{
		enforceMode(M_REQ, M_AUTH_REP);
		
		SessionIDOption *opt = dynamic_cast<SessionIDOption *>(mandatoryOpt.get());
		if (!opt)
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
	std::unique_ptr<IdempotenceRequestOption>     requestOpt;
	std::unique_ptr<IdempotenceExpenditureOption> expenditureOpt;
	std::unique_ptr<IdempotenceWindowOption>      windowOpt;
	std::unique_ptr<Option>                       replyOpt;
	
public:
	IdempotenceOptionSet(OptionSet *owner);
	
	void request(uint32_t size);
	
	uint32_t requestedSize() const
	{
		if (!requestOpt)
			return 0;
		return requestOpt->getWinSize();
	}
	
	void setToken(uint32_t token);
	
	boost::optional<uint32_t> getToken() const
	{
		if (!expenditureOpt)
			return {};
		return expenditureOpt->getToken();
	}
	
	void advertise(uint32_t base, uint32_t size);
	
	uint32_t advertisedBase() const
	{
		if (!windowOpt)
			return 0;
		return windowOpt->getWinBase();
	}
	
	uint32_t advertisedSize() const
	{
		if (!windowOpt)
			return 0;
		return windowOpt->getWinSize();
	}
	
	void setReply(bool accepted);
	
	boost::optional<bool> getReply() const
	{
		if (dynamic_cast<const IdempotenceAcceptedOption *>(replyOpt.get()) != nullptr)
			return true;
		if (dynamic_cast<const IdempotenceRejectedOption *>(replyOpt.get()) != nullptr)
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
		if (!req)
			return nullptr;
		return req->getUsername();
	}
	
	const std::string *getPassword() const
	{
		if (!req)
			return nullptr;
		return req->getPassword();
	}
	
	void setReply(bool success);
	
	boost::optional<bool> getReply() const
	{
		if (!reply)
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
		if (!advertOption)
			return &EMPTY_SET;
		
		return advertOption->getMethods();
	}
	
	void advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen);

	uint16_t getInitialDataLen() const
	{
		if (!advertOption)
			return 0;
		return advertOption->getInitialDataLen();
	}
	
	void select(SOCKS6Method method);
	
	SOCKS6Method getSelected() const
	{
		if (!selectOption)
			return SOCKS6_METHOD_NOAUTH;
		return selectOption->getMethod();
	}
};

class ResolutionOptionSet: public OptionSetBase
{
	std::unique_ptr<ResolutionRequestOption> requestOption;
	std::unique_ptr<IPv4ResolutionOption>    ipv4Option;
	std::unique_ptr<IPv6ResolutionOption>    ipv6Option;
	std::unique_ptr<DomainResolutionOption>  domainOption;

public:
	ResolutionOptionSet(OptionSet *owner);

	void request();

	bool requested() const
	{
		return requestOption.get() != nullptr;
	}

	void setIPv4(const std::list<in_addr> &ipv4);

	const std::list<in_addr> *getIPv4()
	{
		static const std::list<in_addr> EMPTY_LIST;

		if (!ipv4Option)
			return &EMPTY_LIST;

		return ipv4Option.get()->getAddresses();
	}

	void setIPv6(const std::list<in6_addr> &ipv6);

	const std::list<in6_addr> *getIPv6()
	{
		static const std::list<in6_addr> EMPTY_LIST;

		if (!ipv6Option)
			return &EMPTY_LIST;

		return ipv6Option.get()->getAddresses();
	}

	void setDomains(const std::list<std::string> &domains);

	const std::list<std::string> *getDomains()
	{
		static const std::list<std::string> EMPTY_LIST;

		if (!domainOption)
			return &EMPTY_LIST;

		return domainOption.get()->getAddresses();
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
	StackOptionSet       stack        { this };
	SessionOptionSet     session      { this };
	IdempotenceOptionSet idempotence  { this };
	UserPasswdOptionSet  userPassword { this };
	AuthMethodOptionSet  authMethods  { this };
	ResolutionOptionSet  resolution   { this };

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
	friend class ResolutionOptionSet;
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
