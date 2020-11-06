includes("examples")
target("st")
  set_kind("static")
  add_files("event.c","io.c","sched.c","sync.c", "stk.c", "key.c")
  if is_plat("windows") then
      if is_arch("x86") then add_files("md_x86.obj") end
  else
      add_files("md.S")
  end
  add_includedirs(".", {interface=true})
  if is_plat("macosx") then add_defines("DARWIN") end
  if is_plat("linux") then add_defines("LINUX") end
