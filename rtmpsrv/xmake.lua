if has_config("httplib") then
target("rtmpsrv")
  set_kind("binary")
  add_deps("st", "librtmp")
  add_options "httplib"
  add_files("rtmpsrv.cpp", "rtmphub.cpp")
end
