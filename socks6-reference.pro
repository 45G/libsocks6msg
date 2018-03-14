TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cc \
    socks6msg.c

HEADERS += \
    socks6.h \
    socks6msg.h
