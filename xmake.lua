is_termux = os.getenv"PREFIX"
is_termux = is_termux and string.find(is_termux, "com.termux")
add_rules("mode.debug", "mode.release")
includes("myst", "rtmpsrv", "stunmsg", "rtmpdump/librtmp")
option("httplib")
  set_default(true)
  add_cxxincludes("httplib/httplib.h")
  set_languages("cxx11")
  add_includedirs("httplib")
