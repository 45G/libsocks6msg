TARGET = socks6msg
TEMPLATE = lib
CONFIG += staticlib
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    options/option.cc \
    options/stackoption.cc \
    util/sanity.cc \
    util/exception.cc \
    options/idempotenceoption.cc \
    options/authmethodoption.cc \
    options/authdataoption.cc \
    options/optionset.cc \
    fields/address.cc \
    fields/string.cc \
    cbindings.cc \
    messages/authreply.cc \
    messages/opreply.cc \
    messages/request.cc \
    messages/usrpasswd.cc \
    messages/version.cc

HEADERS += \
    socks6.h \
    socks6msg.h \
    socks6msg.hh \
    options/option.hh \
    options/stackoption.hh \
    util/sanity.hh \
    util/exception.hh \
    options/idempotenceoption.hh \
    options/authmethodoption.hh \
    util/bytebuffer.hh \
    options/authdataoption.hh \
    options/optionset.hh \
    fields/address.hh \
    fields/string.hh \
    messages/authreply.hh \
    messages/opreply.hh \
    messages/request.hh \
    messages/usrpasswd.hh \
    messages/version.hh

unix {
    headers.path = /usr/local/include/socks6msg
    headers.files += $$HEADERS
    INSTALLS += headers
    exists(/usr/local/lib64) {
        target.path = /usr/local/lib64
    }
    else {
        target.path = /usr/local/lib
    }
    INSTALLS += target
}
