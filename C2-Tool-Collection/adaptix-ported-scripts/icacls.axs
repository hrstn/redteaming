var metadata = {
    name: "Icacls",
    description: "Quick in-process DACL/rights enumeration (icacls-style) for a path"
};

// icacls <path> [-r depth]   — depth 0 = this path only; depth N = recurse N levels.
var cmd_icacls = ax.create_command("icacls", "Quick icacls: enumerate owner + DACL ACEs (rights letters, inheritance flags, DENY) on a file/dir", "icacls C:\\Users\\Public -r 2");
cmd_icacls.addArgString("path", true, "File or directory path");
cmd_icacls.addArgFlagString("-r", "depth", "Recurse N directory levels (0 = this path only)", "0");
cmd_icacls.setPreHook(function (id, cmdline, parsed_json) {
    var path  = parsed_json["path"];
    var depth = parseInt(parsed_json["depth"] || "0", 10); if (isNaN(depth)) depth = 0;
    if (depth < 0) depth = 0; if (depth > 8) depth = 8;
    var bof_params = ax.bof_pack("wstr,int", [path, depth]);
    var bof_path   = ax.script_dir() + "Icacls." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: icacls ${path} (depth ${depth})`);
});

var group_icacls = ax.create_commands_group("Icacls-BOF", [cmd_icacls]);
ax.register_commands_group(group_icacls, ["beacon", "gopher", "NoNameAx"], ["windows"], []);