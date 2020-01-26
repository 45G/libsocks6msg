#ifndef SOCKS6MSG_OPTIONSET_HH
#define SOCKS6MSG_OPTIONSET_HH

#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <optional>
#include <variant>
#include "option.hh"
#include "stackoption.hh"
#include "idempotenceoption.hh"
#include "authmethodoption.hh"
#include "authdataoption.hh"
#include "sessionoption.hh"

namespace S6M
{

//TODO: this is waaaaaay too bloated

class OptionList
{
protected:
	boost::intrusive::list<Option, boost::intrusive::constant_time_size<false>> options;
	size_t optionsSize = 0;
	
public:
	void registerOption(Option *option)
	{
		if (optionsSize + option->packedSize() > SOCKS6_OPTIONS_LENGTH_MAX)
			throw std::length_error("Option would not fit");
		options.push_back(*option);
		optionsSize += option->packedSize();
	}
};

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
	OptionList *optionList;
	Mode mode;
	
	void enforceMode(Mode mode1) const
	{
		if (mode != mode1)
			throw std::logic_error("Option not available");
	}
	
	void enforceMode(Mode mode1, Mode mode2) const
	{
		if (mode != mode1 && mode != mode2)
			throw std::logic_error("Option not available");
	}
	
	template <typename T>
	static T &vacant(T &t)
	{
		if (t)
			throw std::logic_error("Option already in place");
		return t;
	}
	
	template <typename T>
	static T &vacantVariant(T &t)
	{
		if (!std::holds_alternative<std::monostate>(t))
			throw std::logic_error("Option already in place");
		return t;
	}
	
	template <typename T, typename ... ARG>
	void commitEmplace(std::optional<T> &field, const ARG &... arg)
	{
		vacant(field).emplace(arg...);
		try
		{
			optionList->registerOption(&field.value());
		}
		catch (...)
		{
			field.reset();
			throw;
		}
	}
	
	template <typename T, typename ... ARG>
	void commitEmplace2(std::optional<T> &field1, std::optional<T> &field2, const ARG &... arg)
	{
		vacant(field1);
		vacant(field2).emplace(arg...);
		field1 = field2;
		try
		{
			optionList->registerOption(&field1.value());
		}
		catch (...)
		{
			field1.reset();
			field2.reset();
			throw;
		}
	}
	
	template <typename T, typename V, typename ... ARG>
	void commitEmplaceV(V &field, const ARG &... arg)
	{
		vacantVariant(field).template emplace<T>(arg...);
		try
		{
			optionList->registerOption(std::get_if<T>(&field));
		}
		catch (...)
		{
			field = std::monostate();
			throw;
		}
	}
	
public:
	OptionSetBase(OptionList *optionList, Mode mode)
		: optionList(optionList), mode(mode) {}
};

class SessionOptionSet: public OptionSetBase
{
	std::variant<std::monostate, SessionRequestOption, SessionIDOption, SessionOKOption, SessionInvalidOption> mandatoryOpt;

	std::optional<SessionTeardownOption>  teardownOpt;
	std::optional<SessionUntrustedOption> untrustedOpt;
	
public:
	using OptionSetBase::OptionSetBase;
	
	void request()
	{
		enforceMode(M_REQ);
		commitEmplaceV<SessionRequestOption>(mandatoryOpt);
	}
	
	bool requested() const
	{
		return std::holds_alternative<SessionRequestOption>(mandatoryOpt);
	}
	
	void tearDown()
	{
		enforceMode(M_REQ);
		commitEmplace(teardownOpt);
	}
	
	bool tornDown() const
	{
		return (bool)teardownOpt;
	}
	
	void setID(const SessionID &id)
	{
		enforceMode(M_REQ, M_AUTH_REP);
		commitEmplaceV<SessionIDOption>(mandatoryOpt, id);
	}
	
	const SessionID *getID() const
	{
		enforceMode(M_REQ, M_AUTH_REP);
		
		const SessionIDOption *opt = std::get_if<SessionIDOption>(&mandatoryOpt);
		if (!opt)
			return nullptr;
		return opt->getID();
	}
	
	void signalOK()
	{
		enforceMode(M_AUTH_REP);
		commitEmplaceV<SessionOKOption>(mandatoryOpt);
	}
	
	bool isOK() const
	{
		return std::holds_alternative<SessionOKOption>(mandatoryOpt);
	}
	
	void signalReject()
	{
		enforceMode(M_AUTH_REP);
		commitEmplaceV<SessionInvalidOption>(mandatoryOpt);
	}
	
	bool rejected() const
	{
		return std::holds_alternative<SessionInvalidOption>(mandatoryOpt);
	}
	
	void setUntrusted()
	{
		enforceMode(M_REQ);
		commitEmplace(untrustedOpt);
	}
	
	bool isUntrusted() const
	{
		return (bool)untrustedOpt;
	}
};

class IdempotenceOptionSet: public OptionSetBase
{
	std::optional<IdempotenceRequestOption>     requestOpt;
	std::optional<IdempotenceExpenditureOption> expenditureOpt;

	std::optional<IdempotenceWindowOption> windowOpt;

	std::variant<std::monostate, IdempotenceAcceptedOption, IdempotenceRejectedOption> replyOpt;
	
public:
	using OptionSetBase::OptionSetBase;
	
	void request(uint32_t size)
	{
		enforceMode(M_REQ);
		commitEmplace(requestOpt, size);
	}
	
	uint32_t requestedSize() const
	{
		if (!requestOpt)
			return 0;
		return requestOpt->getWinSize();
	}
	
	void setToken(uint32_t token)
	{
		enforceMode(M_REQ);
		commitEmplace(expenditureOpt, token);
	}
	
	std::optional<uint32_t> getToken() const
	{
		if (!expenditureOpt)
			return {};
		return expenditureOpt->getToken();
	}
	
	void advertise(std::pair<uint32_t, uint32_t> window)
	{
		enforceMode(M_AUTH_REP);
		commitEmplace(windowOpt, window);
	}
	
	std::pair<uint32_t, uint32_t> getAdvertised() const
	{
		if (!windowOpt)
			return { 0, 0 };
		return windowOpt->getWindow();
	}
	
	void setReply(bool accepted)
	{
		enforceMode(M_AUTH_REP);
		if (accepted)
		{
			commitEmplaceV<IdempotenceAcceptedOption>(replyOpt);
		}
		else
		{
			commitEmplaceV<IdempotenceRejectedOption>(replyOpt);
		}
	}
	
	std::optional<bool> getReply() const
	{
		if (std::holds_alternative<IdempotenceAcceptedOption>(replyOpt))
			return true;
		if (std::holds_alternative<IdempotenceRejectedOption>(replyOpt))
			return false;
		return {};
	}
};

template <typename OPT>
class StackOptionPair: public OptionSetBase
{
	std::optional<OPT> clientProxy;
	std::optional<OPT> proxyRemote;
	
public:
	typedef OPT Option;
	
	using OptionSetBase::OptionSetBase;
	
	void set(SOCKS6StackLeg leg, typename OPT::Value value)
	{
		enforceMode(M_REQ, M_AUTH_REP);
		switch(leg)
		{
		case SOCKS6_STACK_LEG_CLIENT_PROXY:
			commitEmplace(clientProxy, leg, value);
			return;
		case SOCKS6_STACK_LEG_PROXY_REMOTE:
			commitEmplace(proxyRemote, leg, value);
			return;
		case SOCKS6_STACK_LEG_BOTH:
			commitEmplace2(clientProxy, proxyRemote, leg, value);
			return;
		}
	}
	
	std::optional<typename OPT::Value> get(SOCKS6StackLeg leg) const
	{
		switch(leg)
		{
		case SOCKS6_STACK_LEG_CLIENT_PROXY:
			if (!clientProxy)
				return {};
			return clientProxy->getValue();
			
		case SOCKS6_STACK_LEG_PROXY_REMOTE:
			if (!proxyRemote)
				return {};
			return clientProxy->getValue();
			
		case SOCKS6_STACK_LEG_BOTH:
			throw std::logic_error("Bad leg");
		}
		return {};
	}
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	void set(typename OPT::Value value)
	{
		set(LEG, value);
	}
	
	template <SOCKS6StackLeg LEG = OPT::LEG_RESTRICT>
	std::optional<typename OPT::Value> get() const
	{
		static_assert (LEG != SOCKS6_STACK_LEG_BOTH, "Option is not restricted to one leg");
		return get(OPT::LEG_RESTRICT);
	}
};

struct StackOptionSet: public OptionSetBase
{
	StackOptionPair<TOSOption>     tos     { optionList, mode };
	StackOptionPair<TFOOption>     tfo     { optionList, mode };
	StackOptionPair<MPOption>      mp      { optionList, mode };
	StackOptionPair<BacklogOption> backlog { optionList, mode };
	
	using OptionSetBase::OptionSetBase;
};

class UserPasswdOptionSet: public OptionSetBase
{
	std::optional<UsernamePasswdReqOption>   req;
	std::optional<UsernamePasswdReplyOption> reply;
	
public:
	using OptionSetBase::OptionSetBase;
	
	void setCredentials(const std::pair<std::string_view, const std::string_view> &creds)
	{
		enforceMode(M_REQ);
		commitEmplace(req, creds);
	}
	
	std::pair<std::string_view, std::string_view> getCredentials() const
	{
		if (!req)
			return {};
		return req->getCredentials();
	}
	
	void setReply(bool success)
	{
		enforceMode(M_AUTH_REP);
		commitEmplace(reply, success);
	}
	
	std::optional<bool> getReply() const
	{
		if (!reply)
			return {};
		return reply->isSuccessful();
	}
};

class AuthMethodOptionSet: public OptionSetBase
{
	std::optional<AuthMethodAdvertOption> advertOption;
	std::optional<AuthMethodSelectOption> selectOption;
	
public:
	using OptionSetBase::OptionSetBase;
	
	const std::set<SOCKS6Method> *getAdvertised() const
	{
		static const std::set<SOCKS6Method> EMPTY_SET;
		if (!advertOption)
			return &EMPTY_SET;
		
		return advertOption->getMethods();
	}
	
	void advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
	{
		enforceMode(M_REQ);
		commitEmplace(advertOption, initialDataLen, methods);
	}

	uint16_t getInitialDataLen() const
	{
		if (!advertOption)
			return 0;
		return advertOption->getInitialDataLen();
	}
	
	void select(SOCKS6Method method)
	{
		enforceMode(M_AUTH_REP);
		commitEmplace(selectOption, method);
	}
	
	SOCKS6Method getSelected() const
	{
		if (!selectOption)
			return SOCKS6_METHOD_NOAUTH;
		return selectOption->getMethod();
	}
};

struct OptionSet: protected OptionList, public OptionSetBase
{
	StackOptionSet       stack        { this, mode };
	SessionOptionSet     session      { this, mode };
	IdempotenceOptionSet idempotence  { this, mode };
	UserPasswdOptionSet  userPassword { this, mode };
	AuthMethodOptionSet  authMethods  { this, mode };
	
	OptionSet(Mode mode)
		: OptionSetBase(this, mode) {}
	
	OptionSet(ByteBuffer *bb, Mode mode, uint16_t optionsLength);
	
	/* intrusive lists fuck this up */
	OptionSet(const OptionSet &) = delete;
	
	/* intrusive lists fuck this up */
	OptionSet &operator =(const OptionSet &) = delete;
	
	void pack(ByteBuffer *bb) const
	{
		for (const Option &option: options)
			option.pack(bb);
	}
	
	size_t packedSize() const
	{
		return optionsSize;
	}
	
	Mode getMode() const
	{
		return mode;
	}
};

}

#endif // SOCKS6MSG_OPTIONSET_HH
