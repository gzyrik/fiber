all: rtmpsrv

MYST_DIR=../myst/DARWIN_$(shell uname -r)_DBG
ST:
	@cd $(MYST_DIR)/.. && $(MAKE) darwin-debug

RTMP_DIR=../rtmpdump
RTMP :
	@cd $(RTMP_DIR) && $(MAKE)

rtmpsrv : server.cpp RTMP ST
	$(CXX) -o $@ $< -O0 -g -I$(MYST_DIR) -I$(RTMP_DIR) -L$(RTMP_DIR)/librtmp -L$(MYST_DIR) -lrtmp -lst
