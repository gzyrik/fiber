all: rtmpsrv

MYST_DIR=../myst/DARWIN_$(shell uname -r)_DBG
MYST:
	@cd ../myst && $(MAKE) darwin-debug

RTMP_DIR=../rtmpdump
RTMP :
	@cd $(RTMP_DIR) && $(MAKE)

CXXFLAGS += -O0 -g -std=c++14 -I$(MYST_DIR) -I$(RTMP_DIR) -L$(RTMP_DIR)/librtmp -L$(MYST_DIR) -lrtmp -lst -lz
rtmpsrv : rtmpsrv.cpp RTMP MYST
	$(CXX) -o $@ $< $(CXXFLAGS)

rtmpush : rtmpush.cpp RTMP MYST
	$(CXX) -o $@ $< $(CXXFLAGS)
