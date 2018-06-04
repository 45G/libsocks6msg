TARGET = socks6msg
TEMPLATE = lib
CONFIG += staticlib
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    socks6msg_option.cc \
    socks6msg_optionset.cc \
    socks6msg_usrpasswd.cc \
    socks6msg_address.cc \
    socks6msg_string.cc \
    socks6msg_request.cc \
    socks6msg_version.cc \
    socks6msg_authreply.cc \
    socks6msg_opreply.cc \
    socks6msg_exception.cc \
    socks6msg_sanity.cc \
    socks6msg_cbindings.cc

HEADERS += \
    socks6.h \
    socks6msg.h \
    socks6msg_option.hh \
    socks6msg_optionset.hh \
    socks6msg_usrpasswd.hh \
    socks6msg_address.hh \
    socks6msg_string.hh \
    socks6msg_request.hh \
    socks6msg_version.hh \
    socks6msg_authreply.hh \
    socks6msg_bytebuffer.hh \
    socks6msg_exception.hh \
    socks6msg_opreply.hh \
    socks6msg.hh \
    socks6msg_sanity.hh

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
