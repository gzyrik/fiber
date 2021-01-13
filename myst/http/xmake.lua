add_deps("st")
target "http"
  set_kind("binary")
  add_files("http.c","picohttpparser.c", "test.c")
