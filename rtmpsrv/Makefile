all: RTMP MYST rtmpsrv
.PHONY : all RTMP MYST clean t0 t1

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
rtmpsrv: rtmpsrv.cpp rtmphub.cpp $(MYST_DIR)/libst.a $(RTMP_DIR)/librtmp/librtmp.a rtmpsrv.h rtmphub.h
	$(CXX) -o $@ $(filter-out %.h,$^) $(CXXFLAGS)

clean:
	@cd $(RTMP_DIR) && $(MAKE) clean

#============================================================================
override v = $(if $(V),,@)
PORT ?= 5562
RTMP_PORT ?= 1935

ifndef IP
IP = 127.0.0.1

define setup
$(v)./rtmpsrv --port=$(HTTP_PORT) --ffmpeg=`which ffmpeg` >test.log 2>&1 &
@sleep 1
$(v)test -n "`lsof -i:$(HTTP_PORT)|grep rtmpsrv`"
endef

define term 
$(v)curl $(HTTP_ADDR)/quit
$(v)test -z "`lsof -i:$(HTTP_PORT)`"
endef

endif

HTTP_PORT = $(PORT)
HTTP_ADDR = $(IP):$(HTTP_PORT)
RTMP_ADDR = $(IP):$(RTMP_PORT)
define test
$(setup)
$(v)curl -X PUT $(HTTP_ADDR)/files -d $(FILES) || echo '** PUT /files Failed !'
$(v)curl $(HTTP_ADDR)/files -s 
$(v)curl -X POST $(HTTP_ADDR)/rtmpsrv?port=$(RTMP_PORT) -d 1
@echo
$(v)-curl $(HTTP_ADDR)/$1
$(v)-test -z "`curl $(HTTP_ADDR)/tasks -s`" || echo '** Get /Task Failed !'
$(term)
$(v)$(RM) test.log
endef

t0: FILES ='\
  (.*)/a0 rtmp://$(RTMP_ADDR)/$$1/.a1 \
  app/a1 http://$(HTTP_ADDR)/tasks/app/a2 \
  app/a2 http://$(HTTP_ADDR)/app/test.flv'
t0: rtmpsrv app/test.flv
	@echo "** Test loopback starting, about 5 seconds ......" && echo
	$(call test,app/a0.flv --output a.flv)
	$(v)diff a.flv app/test.flv
	@echo && echo '** Test passed.'
	$(v)$(RM) a.flv

t1: FILES ='app/ff "ffmpeg -i app/test.flv >ff.log"'
t1: rtmpsrv app/test.flv
	@echo "** Test ffmpeg starting, about 5 seconds ......" && echo
	$(call test,app/ff.flv --output a.flv)
	$(v)test `du -s a.flv|awk '{print $$1}'` \
	     -ge `du -s app/test.flv|awk '{print $$1}'`
	@echo && echo '** Test passed.'
	$(v)$(RM) a.flv ff.log
