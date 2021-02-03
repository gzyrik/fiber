add_deps("st")
target "http"
  set_kind("binary")
  add_files("http.c","http_parse.c", "sha1.c")
  add_files("test.c")
