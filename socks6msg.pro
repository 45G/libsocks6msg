TARGET = socks6msg
TEMPLATE = lib
CONFIG += staticlib
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += fields messages options util

SOURCES += \
    options/option.cc \
    options/stackoption.cc \
    options/idempotenceoption.cc \
    options/authmethodoption.cc \
    options/authdataoption.cc \
    options/optionset.cc \
    fields/address.cc \
    cbindings.cc \
    options/sessionoption.cc

HEADERS += \
    fields/versionchecker.hh \
    messages/messagebase.hh \
    socks6.h \
    socks6msg.h \
    socks6msg.hh \
    options/option.hh \
    options/stackoption.hh \
    util/sanity.hh \
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
    messages/version.hh \
    options/sessionoption.hh \
    util/byteorder.hh \
    util/exceptions.hh \
    fields/padded.hh \
    util/restrictedint.hh \
    messages/datagramheader.hh

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

DISTFILES += \
    README.md
