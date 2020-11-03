set_languages("cxx11")
set_kind("binary")
add_deps("st")

if has_config("httplib") then
target "websrv"
  add_options "httplib"
  add_files "websrv.cpp"
end

target "go1"
  add_files("go1.cpp","go0.cpp")

target("go2", {files = "go2.cpp"})
target("go3", {files = "go3.cpp"})
target("go-echo", {files = "go_echo.cpp"})

target("go-chan")
  add_files("go_chan.cpp","go0.cpp")

target("proxy", {files = "proxy.c"})

target("lookupdns")
  add_files("lookupdns.c","res.c")
  if not is_termux then add_syslinks("resolv") end
