all: RTMP MYST rtmpsrv
.PHONY : all RTMP MYST clean test

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
RTMP:
	@cd $(RTMP_DIR) && $(MAKE)

CXXFLAGS += -O0 -g -std=c++11 -I$(MYST_DIR) -I$(RTMP_DIR) -lz -ldl
rtmpsrv: rtmpsrv.cpp rtmphub.cpp $(MYST_DIR)/libst.a $(RTMP_DIR)/librtmp/librtmp.a
	$(CXX) -o $@ $^ $(CXXFLAGS)

clean:
	@cd $(RTMP_DIR) && $(MAKE) clean

test: HOST:=127.0.0.1:5563
test: V:=$(if $(V),,@)
test: rtmpsrv app/test.flv
	$(V)./rtmpsrv --port=5563 --rtmpsrv=1936 >test.log 2>&1  &
	@echo '** Test starting, about 5 seconds ......'
	$(V)curl -X PUT $(HOST)/files -d "\
		app/a0 rtmp://127.0.0.1:1936/app/a1 \
		app/a1 http://$(HOST)/tasks/app/a2 \
		app/a2 http://$(HOST)/app/test.flv"
	$(V)curl $(HOST)/app/a0.flv --output a.flv
	$(V)test -z `curl $(HOST)/tasks -s`
	$(V)curl $(HOST)/quit
	$(V)diff a.flv app/test.flv && $(RM) a.flv test.log
	@echo '** Test passed.'
