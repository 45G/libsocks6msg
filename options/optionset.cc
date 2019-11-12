#include <arpa/inet.h>
#include "optionset.hh"


using namespace std;

namespace S6M
{

template <typename T>
T &vacant(T &t)
{
	if (t)
		throw std::logic_error("Option already in place");
	return t;
}

template <typename T>
T &vacantVariant(T &t)
{
	if (!holds_alternative<monostate>(t))
		throw std::logic_error("Option already in place");
	return t;
}

#define COMMIT_OPT(FIELD, WHAT) \
{ \
	vacant(FIELD) = (WHAT); \
	try \
	{ \
		owner->registerOption(&(FIELD).value()); \
	} \
	catch (...) \
	{ \
		(FIELD).reset(); \
		throw; \
	} \
}

#define COMMIT_OPT2(FIELD1, FIELD2, WHAT) \
{ \
	vacant(FIELD1); \
	vacant(FIELD2); \
	(FIELD1) = (WHAT); \
	(FIELD2) = (FIELD1); \
	try \
	{ \
		owner->registerOption(&(FIELD1).value()); \
	} \
	catch (...) \
	{ \
		(FIELD1).reset(); \
		(FIELD2).reset(); \
		throw; \
	} \
}

#define COMMIT_VARIANT(FIELD, TYPE, WHAT) \
{ \
	vacantVariant(FIELD); \
	(FIELD) = (WHAT); \
	try \
	{ \
		owner->registerOption(get_if<TYPE>(&FIELD)); \
	} \
	catch (...) \
	{ \
		(FIELD) = monostate(); \
		throw; \
	} \
}

void OptionSetBase::enforceMode(OptionSet::Mode mode1) const
{
	if (mode != mode1)
		throw logic_error("Option not available");
}

void OptionSetBase::enforceMode(OptionSet::Mode mode1, OptionSet::Mode mode2) const
{
	if (mode != mode1 && mode != mode2)
		throw logic_error("Option not available");
}

OptionSet::OptionSet(ByteBuffer *bb, Mode mode, uint16_t optionsLength)
	: OptionSetBase(this, mode)
{
	if (optionsLength > SOCKS6_OPTIONS_LENGTH_MAX)
		throw invalid_argument("Bad options length");
	ByteBuffer optsBB(bb->get<uint8_t>(optionsLength), optionsLength);
	
	while (optsBB.getUsed() < optsBB.getTotalSize())
	{
		SOCKS6Option *opt;

		try
		{
			opt = optsBB.get<SOCKS6Option>();

			/* bad option length wrecks remaining options */
			size_t optLen = ntohs(opt->len);
			if (optLen < sizeof(SOCKS6Option))
				throw length_error("Option too short");
			if (optLen % SOCKS6_ALIGNMENT != 0)
				throw length_error("Option not aligned");

			optsBB.get<uint8_t>(optLen - sizeof(SOCKS6Option));
		}
		catch (length_error &)
		{
			break;
		}
		
		try
		{
			Option::incrementalParse(opt, this);
		}
		catch (invalid_argument &) {}
	}
}

void OptionSet::pack(ByteBuffer *bb) const
{
	for (Option *option: options)
		option->pack(bb);
}

SessionOptionSet::SessionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void SessionOptionSet::request()
{
	enforceMode(M_REQ);
	COMMIT_VARIANT(mandatoryOpt, SessionRequestOption, SessionRequestOption());
}

void SessionOptionSet::tearDown()
{
	enforceMode(M_REQ);
	COMMIT_OPT(teardownOpt, SessionTeardownOption());
}

void SessionOptionSet::setID(const std::vector<uint8_t> &ticket)
{
	enforceMode(M_REQ, M_AUTH_REP);
	COMMIT_VARIANT(mandatoryOpt, SessionIDOption, SessionIDOption(ticket));
}

void SessionOptionSet::signalOK()
{
	enforceMode(M_AUTH_REP);
	COMMIT_VARIANT(mandatoryOpt, SessionOKOption, SessionOKOption());
}

void SessionOptionSet::signalReject()
{
	enforceMode(M_AUTH_REP);
	COMMIT_VARIANT(mandatoryOpt, SessionInvalidOption, SessionInvalidOption());
}

void SessionOptionSet::setUntrusted()
{
	enforceMode(M_REQ);
	COMMIT_OPT(untrustedOpt, SessionUntrustedOption());
}

IdempotenceOptionSet::IdempotenceOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void IdempotenceOptionSet::request(uint32_t size)
{
	enforceMode(M_REQ);
	COMMIT_OPT(requestOpt, IdempotenceRequestOption(size));
}

void IdempotenceOptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	COMMIT_OPT(expenditureOpt, IdempotenceExpenditureOption(token));
}

void IdempotenceOptionSet::advertise(std::pair<uint32_t, uint32_t> window)
{
	enforceMode(M_AUTH_REP);
	COMMIT_OPT(windowOpt, IdempotenceWindowOption(window));
}

void IdempotenceOptionSet::setReply(bool accepted)
{
	enforceMode(M_AUTH_REP);
	if (accepted)
	{
		COMMIT_VARIANT(replyOpt, IdempotenceAcceptedOption, IdempotenceAcceptedOption());
	}
	else
	{
		COMMIT_VARIANT(replyOpt, IdempotenceAcceptedOption, IdempotenceRejectedOption());
	}
}

template <typename T>
StackOptionPair<T>::StackOptionPair(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

template <typename T>
void StackOptionPair<T>::set(SOCKS6StackLeg leg, typename T::Value value)
{
	enforceMode(M_REQ, M_AUTH_REP);
	switch(leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		COMMIT_OPT(clientProxy, T(leg, value));
		return;
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		COMMIT_OPT(proxyRemote, T(leg, value));
		return;
	case SOCKS6_STACK_LEG_BOTH:
		COMMIT_OPT2(clientProxy, proxyRemote, T(leg, value));
		return;
	}
}

template <typename T>
optional<typename T::Value> StackOptionPair<T>::get(SOCKS6StackLeg leg) const
{
	enforceMode(M_REQ, M_AUTH_REP);
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
		throw logic_error("Bad leg");
	}
	return {};
}

StackOptionSet::StackOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

template class StackOptionPair<TOSOption>;
template class StackOptionPair<TFOOption>;
template class StackOptionPair<MPOption>;
template class StackOptionPair<BacklogOption>;

UserPasswdOptionSet::UserPasswdOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void UserPasswdOptionSet::setCredentials(const string &user, const string &passwd)
{
	enforceMode(M_REQ);
	COMMIT_OPT(req, UsernamePasswdReqOption(user, passwd));
}

void UserPasswdOptionSet::setReply(bool success)
{
	enforceMode(M_AUTH_REP);
	COMMIT_OPT(reply, UsernamePasswdReplyOption(success));
}

AuthMethodOptionSet::AuthMethodOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void AuthMethodOptionSet::advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
{
	enforceMode(M_REQ);
	COMMIT_OPT(advertOption, AuthMethodAdvertOption(initialDataLen, methods));
}

void AuthMethodOptionSet::select(SOCKS6Method method)
{
	enforceMode(M_AUTH_REP);
	COMMIT_OPT(selectOption, AuthMethodSelectOption(method));
}

}
