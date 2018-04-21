TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    socks6msg.cc \
    main.c \
    socks6msg_option.cc \
    socks6msg_base.cc

HEADERS += \
    socks6.h \
    socks6msg.h \
    socks6msg_base.hh \
    socks6msg_option.hh
