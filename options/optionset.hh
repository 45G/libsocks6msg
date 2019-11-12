#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <memory>
#include <optional>
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
		return dynamic_cast<SessionRequestOption *>(mandatoryOpt.get());
	}
	
	void tearDown();
	
	bool tornDown() const
	{
		return (bool)teardownOpt;
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
		return dynamic_cast<SessionOKOption *>(mandatoryOpt.get());
	}
	
	void signalReject();
	
	bool rejected() const
	{
		return dynamic_cast<SessionInvalidOption *>(mandatoryOpt.get());
	}
	
	void setUntrusted();
	
	bool isUntrusted() const
	{
		return (bool)untrustedOpt;
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
	
	std::optional<uint32_t> getToken() const
	{
		if (!expenditureOpt)
			return {};
		return expenditureOpt->getToken();
	}
	
	void advertise(std::pair<uint32_t, uint32_t> window);
	
	std::pair<uint32_t, uint32_t> getAdvertised() const
	{
		if (!windowOpt)
			return { 0, 0 };
		return windowOpt->getWindow();
	}
	
	void setReply(bool accepted);
	
	std::optional<bool> getReply() const
	{
		if (dynamic_cast<const IdempotenceAcceptedOption *>(replyOpt.get()))
			return true;
		if (dynamic_cast<const IdempotenceRejectedOption *>(replyOpt.get()))
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
	
	std::optional<typename OPT::Value> get(SOCKS6StackLeg leg) const;
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	void set(typename OPT::Value value)
	{
		static_assert (LEG != SOCKS6_STACK_LEG_BOTH, "Option is not restricted to one leg");
		set(LEG, value);
	}
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	std::optional<typename OPT::Value> get() const
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
	
	std::optional<bool> getReply() const
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
