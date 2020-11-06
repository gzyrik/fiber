is_termux = os.getenv"PREFIX"
is_termux = is_termux and string.find(is_termux, "com.termux")
if is_plat("windows") then
--add_cflags("/GS-",{force=true})
end
add_rules("mode.debug", "mode.release", "mode.releasedbg")
if is_mode("release") then add_defines("NDEBUG") end
includes("myst", "rtmpsrv", "stunsrv", "rtmpdump/librtmp")
option("httplib")
  set_default(true)
  add_cxxincludes("httplib/httplib.h")
  set_languages("cxx11")
  add_includedirs("httplib")
