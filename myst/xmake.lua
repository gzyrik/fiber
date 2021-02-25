is_termux = os.getenv"PREFIX"
is_termux = is_termux and string.find(is_termux, "com.termux")

if is_mode("release") then add_defines("NDEBUG") end
includes("examples", "http")
target("st")
  add_files("event.c","io.c","sched.c","sync.c", "stk.c", "key.c")
  add_files("http.c", "http_parse.c", "sha1.c")
  add_files("res.c")
  if is_plat("windows") then
      set_kind("shared")
      add_shflags("/def:myst/libst.def")
      if is_arch("x86") then 
          add_files("md_x86.obj")
      else
          add_files("md_x64.obj")
      end
      add_files("win_dns.c")
      add_syslinks("ws2_32", "winmm", "advapi32")
      -- add_syslinks("ws2_32", "winmm", {interface=true})
  else
      set_kind("static")
      add_files("md.S")
      -- if not is_termux then add_syslinks("resolv", {interface=true}) end
  end
  add_includedirs(".", {interface=true})
  if is_plat("macosx") then add_defines("DARWIN") end
  if is_plat("linux") then
      add_defines("LINUX")
      add_syslinks("dl", {interface=true})
  end
