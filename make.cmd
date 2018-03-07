rem make [x64]
@echo off
if not defined INCLUDE call "%VS140COMNTOOLS%..\..\VC\vcvarsall.bat" %1
set coctx_swap=coctx_swap32.obj
if "%Platform%"=="X64" set coctx_swap=coctx_swap64.obj
@echo on
cl /nologo /c /Od /Z7 /EHsc coctx_test.cpp test.cpp coctx.cpp coroutine.cpp ucontext_w.cpp
link /nologo /DEBUG /PDB:coctx_test.pdb /out:coctx_test.exe coctx_test.obj coctx.obj %coctx_swap%
link /nologo /DEBUG /PDB:test.pdb /out:test.exe test.obj coctx.obj %coctx_swap% coroutine.obj ucontext_w.obj
coctx_test.exe
test.exe
