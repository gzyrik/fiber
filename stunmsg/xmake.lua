target("stunmsg")
  set_kind("static")
  add_files("src/*.c")
  add_includedirs("include", {public=true})
