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

template <typename T, typename L>
void OptionSetBase::commit(optional<T> &field, L lambda)
{
	vacant(field) = lambda();
	try
	{
		owner->registerOption(&field.value());
	}
	catch (...)
	{
		field.reset();
		throw;
	}
}

template <typename T, typename L>
void OptionSetBase::commit(optional<T> &field1, optional<T> &field2, L lambda)
{
	vacant(field1);
	vacant(field2) = lambda();
	field1 = field2;
	try
	{
		owner->registerOption(&field1.value());
	}
	catch (...)
	{
		field1.reset();
		field2.reset();
		throw;
	}
}

template <typename V, typename L>
void OptionSetBase::commitVariant(V &field, L lambda)
{
	vacantVariant(field) = lambda();
	try
	{
		owner->registerOption(get_if<decltype(lambda())>(&field));
	}
	catch (...)
	{
		field = monostate();
		throw;
	}
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
	for (const Option &option: options)
		option.pack(bb);
}

SessionOptionSet::SessionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void SessionOptionSet::request()
{
	enforceMode(M_REQ);
	commitVariant(mandatoryOpt, []() { return SessionRequestOption(); });
}

void SessionOptionSet::tearDown()
{
	enforceMode(M_REQ);
	commit(teardownOpt, [](){ return SessionTeardownOption(); });
}

void SessionOptionSet::setID(const std::vector<uint8_t> &ticket)
{
	enforceMode(M_REQ, M_AUTH_REP);
	commitVariant(mandatoryOpt, [&]() { return SessionIDOption(ticket); });
}

void SessionOptionSet::signalOK()
{
	enforceMode(M_AUTH_REP);
	commitVariant(mandatoryOpt, []() { return SessionOKOption(); });
}

void SessionOptionSet::signalReject()
{
	enforceMode(M_AUTH_REP);
	commitVariant(mandatoryOpt, []() { return SessionInvalidOption(); });
}

void SessionOptionSet::setUntrusted()
{
	enforceMode(M_REQ);
	commit(untrustedOpt, []() { return SessionUntrustedOption(); });
}

IdempotenceOptionSet::IdempotenceOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void IdempotenceOptionSet::request(uint32_t size)
{
	enforceMode(M_REQ);
	commit(requestOpt, [=]() { return IdempotenceRequestOption(size); });
}

void IdempotenceOptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	commit(expenditureOpt, [=]() { return IdempotenceExpenditureOption(token); });
}

void IdempotenceOptionSet::advertise(std::pair<uint32_t, uint32_t> window)
{
	enforceMode(M_AUTH_REP);
	commit(windowOpt, [=]() { return IdempotenceWindowOption(window); });
}

void IdempotenceOptionSet::setReply(bool accepted)
{
	enforceMode(M_AUTH_REP);
	if (accepted)
	{
		commitVariant(replyOpt, []() { return IdempotenceAcceptedOption(); });
	}
	else
	{
		commitVariant(replyOpt, []() { return IdempotenceRejectedOption(); });
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
		commit(clientProxy, [&]() { return T(leg, value); });
		return;
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		commit(proxyRemote, [&]() { return T(leg, value); });
		return;
	case SOCKS6_STACK_LEG_BOTH:
		commit(clientProxy, proxyRemote, [&]() { return T(leg, value); });
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
	commit(req, [&]() { return UsernamePasswdReqOption(user, passwd); });
}

void UserPasswdOptionSet::setReply(bool success)
{
	enforceMode(M_AUTH_REP);
	commit(reply, [=]() { return UsernamePasswdReplyOption(success); });
}

AuthMethodOptionSet::AuthMethodOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void AuthMethodOptionSet::advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
{
	enforceMode(M_REQ);
	commit(advertOption, [&]() { return AuthMethodAdvertOption(initialDataLen, methods); });
}

void AuthMethodOptionSet::select(SOCKS6Method method)
{
	enforceMode(M_AUTH_REP);
	commit(selectOption, [=]() { return AuthMethodSelectOption(method); });
}

}
