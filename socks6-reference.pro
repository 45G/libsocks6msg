TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    socks6msg.cc \
    main.c \
    socks6msg_option.cc \
    socks6msg_base.cc \
    socks6msg_optionset.cc \
    socks6msg_usrpasswd.cc \
    socks6msg_address.cc

HEADERS += \
    socks6.h \
    socks6msg.h \
    socks6msg_base.hh \
    socks6msg_option.hh \
    socks6msg_optionset.hh \
    socks6msg_usrpasswd.hh \
    socks6msg_address.hh
