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
	OptionList *list;
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
	
	template <typename T, typename L>
	void commit(std::optional<T> &field, L lambda)
	{
		vacant(field) = lambda();
		try
		{
			list->registerOption(&field.value());
		}
		catch (...)
		{
			field.reset();
			throw;
		}
	}
	
	template <typename T, typename L>
	void commit(std::optional<T> &field1, std::optional<T> &field2, L lambda)
	{
		vacant(field1);
		vacant(field2) = lambda();
		field1 = field2;
		try
		{
			list->registerOption(&field1.value());
		}
		catch (...)
		{
			field1.reset();
			field2.reset();
			throw;
		}
	}
	
	template <typename V, typename L>
	void commitVariant(V &field, L lambda)
	{
		vacantVariant(field) = lambda();
		try
		{
			list->registerOption(std::get_if<decltype(lambda())>(&field));
		}
		catch (...)
		{
			field = std::monostate();
			throw;
		}
	}
	
public:
	OptionSetBase(OptionList *list, Mode mode)
		: list(list), mode(mode) {}
};

class SessionOptionSet: public OptionSetBase
{
	std::variant<std::monostate, SessionRequestOption, SessionIDOption, SessionOKOption, SessionInvalidOption> mandatoryOpt;

	std::optional<SessionTeardownOption>  teardownOpt;
	std::optional<SessionUntrustedOption> untrustedOpt;
	
public:
	using OptionSetBase::OptionSetBase;
	
	void request();
	
	bool requested() const
	{
		return std::holds_alternative<SessionRequestOption>(mandatoryOpt);
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
		
		const SessionIDOption *opt = std::get_if<SessionIDOption>(&mandatoryOpt);
		if (!opt)
			return nullptr;
		return opt->getTicket();
	}
	
	void signalOK();
	
	bool isOK() const
	{
		return std::holds_alternative<SessionOKOption>(mandatoryOpt);
	}
	
	void signalReject();
	
	bool rejected() const
	{
		return std::holds_alternative<SessionInvalidOption>(mandatoryOpt);
	}
	
	void setUntrusted();
	
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
		if (std::holds_alternative<IdempotenceAcceptedOption>(replyOpt))
			return true;
		if (std::holds_alternative< IdempotenceRejectedOption>(replyOpt))
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

struct StackOptionSet: public OptionSetBase
{
	StackOptionPair<TOSOption>     tos     { list, mode };
	StackOptionPair<TFOOption>     tfo     { list, mode };
	StackOptionPair<MPOption>      mp      { list, mode };
	StackOptionPair<BacklogOption> backlog { list, mode };
	
	using OptionSetBase::OptionSetBase;
};

class UserPasswdOptionSet: public OptionSetBase
{
	std::optional<UsernamePasswdReqOption>   req;
	std::optional<UsernamePasswdReplyOption> reply;
public:
	using OptionSetBase::OptionSetBase;
	
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

struct OptionSet: public OptionSetBase, protected OptionList
{
	StackOptionSet       stack        { this, mode };
	SessionOptionSet     session      { this, mode };
	IdempotenceOptionSet idempotence  { this, mode };
	UserPasswdOptionSet  userPassword { this, mode };
	AuthMethodOptionSet  authMethods  { this, mode };
	
	OptionSet(Mode mode)
		: OptionSetBase(this, mode) {}
	
	OptionSet(ByteBuffer *bb, Mode mode, uint16_t optionsLength);
	
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
	
	friend class OptionSetBase;
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
