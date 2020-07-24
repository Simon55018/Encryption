#-------------------------------------------------
#
# Project created by QtCreator 2020-07-24T14:52:32
#
#-------------------------------------------------

QT       -= gui

TARGET = Encryption
TEMPLATE = lib
CONFIG += staticlib

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        src/CAES.cpp

HEADERS += \
        include/CAES.h
unix {
    target.path = /usr/lib
    INSTALLS += target
}

#begin 输出路径
CONFIG(debug, debug|release){
    MOC_DIR = ./GeneratedFiles/debug
    OBJECTS_DIR = ./debug
    win32:DESTDIR = $$PWD/../Win32/Debug/lib
    unix:DESTDIR = $$PWD/../Unix/Debug/lib
}
else: CONFIG(release, debug|release){
    MOC_DIR = ./GeneratedFiles/release
    OBJECTS_DIR = ./release
    win32:DESTDIR = $$PWD/../Win32/Release/lib
    unix:DESTDIR = $$PWD/../Unix/Release/lib

    #release版本不打印对应调试消息
    DEFINES += QT_NO_DEBUG_OUTPUT
}
#end
