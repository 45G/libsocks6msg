#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include "optionset.hh"


using namespace std;
using namespace boost;

namespace S6M
{

template <typename T>
void ensureVacant(const std::unique_ptr<T> &ptr)
{
	if (ptr.get() != nullptr)
		throw std::logic_error("Option already in place");
}

template <typename T>
void ensureVacant(const std::shared_ptr<T> &ptr)
{
	if (ptr.get() != nullptr)
		throw std::logic_error("Option already in place");
}

#define COMMIT(FIELD, WHAT) \
{ \
	ensureVacant(FIELD); \
	(FIELD).reset(WHAT); \
	try \
	{ \
		owner->registerOption((FIELD).get()); \
	} \
	catch (...) \
	{ \
		(FIELD).reset(); \
		throw; \
	} \
}

#define COMMIT2(FIELD1, FIELD2, WHAT) \
{ \
	ensureVacant(FIELD1); \
	ensureVacant(FIELD2); \
	(FIELD1).reset(WHAT); \
	(FIELD2) = (FIELD1); \
	try \
	{ \
		owner->registerOption((FIELD1).get()); \
	} \
	catch (...) \
	{ \
		(FIELD1).reset(); \
		(FIELD2).reset(); \
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
	BOOST_FOREACH(Option *option, options)
	{
		option->pack(bb);
	}
}

SessionOptionSet::SessionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void SessionOptionSet::request()
{
	enforceMode(M_REQ);
	COMMIT(mandatoryOpt, new SessionRequestOption());
}

void SessionOptionSet::tearDown()
{
	enforceMode(M_REQ);
	COMMIT(teardownOpt, new SessionTeardownOption());
}

void SessionOptionSet::setID(const std::vector<uint8_t> &ticket)
{
	enforceMode(M_REQ, M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionIDOption(ticket));
}

void SessionOptionSet::signalOK()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionOKOption());
}

void SessionOptionSet::signalReject()
{
	enforceMode(M_AUTH_REP);
	COMMIT(mandatoryOpt, new SessionInvalidOption());
}

void SessionOptionSet::setUntrusted()
{
	enforceMode(M_REQ);
	COMMIT(untrustedOpt, new SessionUntrustedOption());
}

IdempotenceOptionSet::IdempotenceOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void IdempotenceOptionSet::request(uint32_t size)
{
	enforceMode(M_REQ);
	COMMIT(requestOpt, new IdempotenceRequestOption(size));
}

void IdempotenceOptionSet::setToken(uint32_t token)
{
	enforceMode(M_REQ);
	COMMIT(expenditureOpt, new IdempotenceExpenditureOption(token));
}

void IdempotenceOptionSet::advertise(uint32_t base, uint32_t size)
{
	enforceMode(M_AUTH_REP);
	COMMIT(windowOpt, new IdempotenceWindowOption(base, size));
}

void IdempotenceOptionSet::setReply(bool accepted)
{
	enforceMode(M_AUTH_REP);
	if (accepted)
	{
		COMMIT(replyOpt, new IdempotenceAcceptedOption());
	}
	else
	{
		COMMIT(replyOpt, new IdempotenceRejectedOption());
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
		COMMIT(clientProxy, new T(leg, value));
		return;
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		COMMIT(proxyRemote, new T(leg, value));
		return;
	case SOCKS6_STACK_LEG_BOTH:
		COMMIT2(clientProxy, proxyRemote, new T(leg, value));
		return;
	}
}

template <typename T>
boost::optional<typename T::Value> StackOptionPair<T>::get(SOCKS6StackLeg leg) const
{
	enforceMode(M_REQ, M_AUTH_REP);
	switch(leg)
	{
	case SOCKS6_STACK_LEG_CLIENT_PROXY:
		if (clientProxy.get() == nullptr)
			return {};
		return clientProxy->getValue();
		
	case SOCKS6_STACK_LEG_PROXY_REMOTE:
		if (proxyRemote.get() == nullptr)
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
	COMMIT(req, new UsernamePasswdReqOption(user, passwd));
}

void UserPasswdOptionSet::setReply(bool success)
{
	enforceMode(M_AUTH_REP);
	COMMIT(reply, new UsernamePasswdReplyOption(success));
}

AuthMethodOptionSet::AuthMethodOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void AuthMethodOptionSet::advertise(const std::set<SOCKS6Method> &methods, uint16_t initialDataLen)
{
	enforceMode(M_REQ);
	COMMIT(advertOption, new AuthMethodAdvertOption(initialDataLen, methods));
}

void AuthMethodOptionSet::select(SOCKS6Method method)
{
	enforceMode(M_AUTH_REP);
	COMMIT(selectOption, new AuthMethodSelectOption(method));
}

ResolutionOptionSet::ResolutionOptionSet(OptionSet *owner)
	: OptionSetBase(owner, owner->mode) {}

void ResolutionOptionSet::request()
{
	enforceMode(M_REQ);
	COMMIT(requestOption, new ResolutionRequestOption());
}

void ResolutionOptionSet::setIPv4(const std::list<in_addr> &ipv4)
{
	enforceMode(M_OP_REP);
	COMMIT(ipv4Option, new IPv4ResolutionOption(ipv4));
}

void ResolutionOptionSet::setIPv6(const std::list<in6_addr> &ipv6)
{
	enforceMode(M_OP_REP);
	COMMIT(ipv6Option, new IPv6ResolutionOption(ipv6));
}

void ResolutionOptionSet::setDomains(const std::list<string> &domains)
{
	enforceMode(M_OP_REP);
	COMMIT(domainOption, new DomainResolutionOption(domains));
}

}
