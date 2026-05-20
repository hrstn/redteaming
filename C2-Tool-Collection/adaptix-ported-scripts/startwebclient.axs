var metadata = {
    name: "StartWebClient",
    description: "Start the WebClient service programmatically from user context"
};

var cmd_startwebclient = ax.create_command("startwebclient", "Start the WebClient (WebDAV) service via a service trigger from user context", "startwebclient");
cmd_startwebclient.setPreHook(function (id, cmdline, parsed_json) {
    var bof_path = ax.script_dir() + "StartWebClient." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: start WebClient service");
});

var group_startwebclient = ax.create_commands_group("StartWebClient-BOF", [cmd_startwebclient]);
ax.register_commands_group(group_startwebclient, ["beacon", "gopher", "kharon"], ["windows"], []);
