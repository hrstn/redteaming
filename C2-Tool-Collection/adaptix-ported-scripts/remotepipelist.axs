var metadata = {
    name: "RemotePipeList",
    description: "List named pipes on a remote system via .NET assembly (x64 only)"
};

// NOTE: Inline .NET assembly execution uses a different Adaptix API than BOFs.
// The execute_alias command verb for .NET assemblies is "execute dotnet" if supported.
// Verify against your Adaptix version. x64 agents only — RemotePipeList.exe is x64-only.
var cmd_remotepipelist = ax.create_command("remotepipelist", "List named pipes on a remote system (.NET assembly, x64 only)", "remotepipelist <targetIP> [username] [password]");
cmd_remotepipelist.addArgString("target",   true,  "Target IP address or hostname");
cmd_remotepipelist.addArgString("username", false, "Optional domain\\username for authenticated access");
cmd_remotepipelist.addArgString("password", false, "Optional password for authenticated access");
cmd_remotepipelist.setPreHook(function (id, cmdline, parsed_json) {
    if (ax.arch(id) !== "x64") {
        ax.log(id, "RemotePipeList requires an x64 agent.");
        return;
    }

    var target   = parsed_json["target"];
    var username = parsed_json["username"] || "";
    var password = parsed_json["password"] || "";

    var exe_args = target;
    if (username !== "") {
        exe_args += " " + username;
        if (password !== "") {
            exe_args += " " + password;
        }
    }

    var exe_path = ax.script_dir() + "RemotePipeList.exe";
    // "execute dotnet" is the assumed Adaptix alias for inline .NET assembly execution.
    // Replace with the correct verb if your Adaptix build uses a different one.
    ax.execute_alias(id, cmdline, `execute dotnet "${exe_path}" "${exe_args}"`, `Task: list named pipes on ${target}`);
});

var group_remotepipelist = ax.create_commands_group("RemotePipeList", [cmd_remotepipelist]);
ax.register_commands_group(group_remotepipelist, ["beacon", "gopher", "kharon"], ["windows"], []);
