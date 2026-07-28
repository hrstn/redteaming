var metadata = {
    name: "",
    description: "",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "AD-BOF/ad.axs");
ax.script_load(path + "AI-BOF/aibof.axs");
ax.script_load(path + "AD-BOF/ad-services.axs");
ax.script_load(path + "Creds-BOF/creds.axs");
ax.script_load(path + "Elevation-BOF/elevate.axs");
ax.script_load(path + "Execution-BOF/execution.axs");
ax.script_load(path + "Injection-BOF/inject.axs");
ax.script_load(path + "LateralMovement-BOF/lateral.axs");
ax.script_load(path + "Postex-BOF/postex.axs");
ax.script_load(path + "Process-BOF/process.axs");
ax.script_load(path + "SAL-BOF/sal.axs");
ax.script_load(path + "SAR-BOF/sar.axs");
ax.script_load(path + "AD-BOF/ADCS-BOF/ADCS.axs");
ax.script_load(path + "AD-BOF/Kerbeus-BOF/kerbeus.axs");
ax.script_load(path + "AD-BOF/LDAP-BOF/LDAP.axs");
ax.script_load(path + "AD-BOF/RelayInformer/RelayInformer.axs");
ax.script_load(path + "AD-BOF/SQL-BOF/SQL.axs");
ax.script_load(path + "Creds-BOF/cookie-monster/cookie-monster.axs");
ax.script_load(path + "Creds-BOF/nanodump/nanodump.axs");
ax.script_load(path + "Execution-BOF/No-Consolation/no_consolation.axs");