"""Exposes the execution platform's hermetic Python 3 interpreter to cargo_build_script."""

def _exec_py_toolchain_impl(ctx):
    dep = ctx.attr.actual
    info = dep[platform_common.TemplateVariableInfo]
    vars = dict(info.variables)
    py3 = vars.get("PYTHON3", "")
    if py3 and not py3.startswith("/"):
        vars["PYTHON3"] = "$${pwd}/" + py3
    return [
        dep[DefaultInfo],
        platform_common.TemplateVariableInfo(vars),
    ]

exec_py_toolchain = rule(
    implementation = _exec_py_toolchain_impl,
    attrs = {
        "actual": attr.label(
            cfg = "exec",
            default = Label("@rules_python//python:current_py_toolchain"),
        ),
    },
)
