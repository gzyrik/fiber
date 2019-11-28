all: rtmpsrv

OS=$(shell uname)
ifeq ($(OS),Linux)
MYST_DIR=../myst/Linux_$(shell uname -r)_DBG
MYST:
	@cd ../myst && $(MAKE) linux-debug
else
MYST_DIR=../myst/DARWIN_$(shell uname -r)_DBG
MYST:
	@cd ../myst && $(MAKE) darwin-debug
endif

RTMP_DIR=../rtmpdump
RTMP :
	@cd $(RTMP_DIR) && $(MAKE)

CXXFLAGS += -O0 -g -std=c++11 -I$(MYST_DIR) -I$(RTMP_DIR) $(MYST_DIR)/libst.a $(RTMP_DIR)/librtmp/librtmp.a -lz -ldl
rtmpsrv : rtmpsrv.cpp rtmphub.cpp RTMP MYST
	$(CXX) -o $@ $(filter %.cpp,$^) $(CXXFLAGS)

clean:
	@cd $(RTMP_DIR) && $(MAKE) clean
