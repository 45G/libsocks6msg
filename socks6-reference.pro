TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    socks6msg.cc \
    main.c \
    socks6msg_option.cc \
    socks6msg_optionset.cc \
    socks6msg_usrpasswd.cc \
    socks6msg_address.cc \
    socks6msg_string.cc \
    socks6msg_request.cc \
    socks6msg_version.cc \
    socks6msg_authreply.cc \
    socks6msg_opreply.cc

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
    socks6msg_opreply.hh
