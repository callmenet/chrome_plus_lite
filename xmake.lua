add_rules("mode.debug", "mode.release")
set_warnings("more")
add_defines("WIN32", "_WIN32", "UNICODE", "_UNICODE")
set_encodings("source:utf-8")
add_cxxflags("/std:c++23preview", {force = true})
set_fpmodels("precise")

add_requires("vcpkg::detours")

if is_mode("release") then
    set_exceptions("none")
    set_optimize("smallest")
    set_runtimes("MT")
    add_defines("NDEBUG")
    add_ldflags("/DYNAMICBASE")
    set_policy("build.optimization.lto", true)
end

target("chrome_plus_lite")
    set_kind("shared")
    set_targetdir("$(builddir)/$(mode)")
    set_basename("version")
    add_packages("vcpkg::detours")
    add_files("src/chrome++_lite.cc")
    add_links("shlwapi", "crypt32", "psapi", "shell32", "propsys", "ole32", "advapi32", "user32")
