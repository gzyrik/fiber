includes("examples")
target("st")
  set_kind("static")
  add_files("event.c","io.c","sched.c","sync.c", "stk.c", "key.c")
  add_files("md.S")
  add_includedirs(".", {interface=true})
  if is_plat("macosx") then add_defines("DARWIN") end
  if is_plat("linux") then add_defines("LINUX") end
