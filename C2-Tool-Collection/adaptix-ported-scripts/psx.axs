var metadata = {
    name: "Psx",
    description: "List all processes with security product summary"
};

// The Psx BOF reads a short integer: 0 = standard listing, 11 = extended listing.
// "short" packs a 16-bit integer matching BeaconDataShort() in the BOF.
var cmd_psx = ax.create_command("psx", "Show information from all processes running on the system", "psx");
cmd_psx.setPreHook(function (id, cmdline, parsed_json) {
    var bof_params = ax.bof_pack("short", [0]);
    var bof_path   = ax.script_dir() + "Psx." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: list process information");
});

var cmd_psxx = ax.create_command("psxx", "Show extended detailed information from all processes running on the system", "psxx");
cmd_psxx.setPreHook(function (id, cmdline, parsed_json) {
    var bof_params = ax.bof_pack("short", [11]);
    var bof_path   = ax.script_dir() + "Psx." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: list extended process information");
});

var group_psx = ax.create_commands_group("Psx-BOF", [cmd_psx, cmd_psxx]);
ax.register_commands_group(group_psx, ["beacon", "gopher", "kharon"], ["windows"], []);
