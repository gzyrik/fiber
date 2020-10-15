is_termux = os.getenv"PREFIX"
is_termux = is_termux and string.find(is_termux, "com.termux")

set_project("state-thread")
includes("examples")
target("st")
  set_kind("static")
  add_files("event.c","io.c","sched.c","sync.c", "stk.c", "key.c")
  add_files("md.S")
  add_includedirs(path.absolute("."), {public=true})
  if is_plat("macosx") then add_defines("DARWIN") end
  if is_plat("linux") then add_defines("LINUX") end
