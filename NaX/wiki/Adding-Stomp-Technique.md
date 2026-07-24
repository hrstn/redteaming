# Adding a Custom Module Stomping Technique

Step-by-step guide for wiring a new compile-time stomping technique through the full stack: UI dropdown, Go plugin, Makefiles, and C beacon/loader code.

---

## 1. Define the Compile-Time Flag

### Top-level Makefile

Set the default **before** `BEACON_TRANSPORT` (which uses `:=` immediate evaluation):

```makefile
# Makefile — BEFORE the := assignment
NAX_MY_TECHNIQUE    ?= 0
BEACON_TRANSPORT := NAX_TRANSPORT_PROFILE=$(NAX_TRANSPORT_PROFILE) NAX_MY_TECHNIQUE=$(NAX_MY_TECHNIQUE)
```

Pass it to the loader sub-make too:

```makefile
LOADER_DEFINES := NAX_STOMP_MODE=$(NAX_STOMP_MODE) NAX_EXEC_MODE=$(NAX_EXEC_MODE) NAX_MY_TECHNIQUE=$(NAX_MY_TECHNIQUE)
```

### Beacon Makefile (`src_beacon/Makefile`)

Add unconditionally to both release and debug CFLAGS:

```makefile
NAX_MY_TECHNIQUE ?= 0
CFLAGS += -DNAX_MY_TECHNIQUE=$(NAX_MY_TECHNIQUE)

# ... later in the debug section ...
DEBUG_CFLAGS += -DNAX_MY_TECHNIQUE=$(NAX_MY_TECHNIQUE)
```

### Beacon Config.h fallback (`src_beacon/include/Config.h`)

For manual builds that don't go through the Go plugin:

```c
#ifndef NAX_MY_TECHNIQUE
#define NAX_MY_TECHNIQUE 0
#endif
```

---

## 2. Add the UI Option (AXScript)

In `src_server/agent_nonameax/ax_config.axs`, inside `GenerateUI()`, Tab 2 (Evasion), Loader group:

### Create the combo widget

```javascript
let comboStompTech = form.create_combo();
comboStompTech.addItems(["Basic (LoadLibraryEx)", "My Technique (description)"]);
```

### Wire enable/disable to the module stomp checkbox

Add `comboStompTech.setEnabled(on)` inside the existing `checkStomp` `stateChanged` handler:

```javascript
form.connect(checkStomp, "stateChanged", function() {
    let on = checkStomp.isChecked();
    comboStompTech.setEnabled(on);   // <-- add this line
    comboStompDll.setEnabled(on);
    checkUnwind.setEnabled(on);
    if (!on) checkUnwind.setChecked(false);
});
```

### Add to the grid layout

Insert a new row after "Module Stomp:" and shift subsequent rows down by 1:

```javascript
loaderLayout.addWidget(form.create_label("Module Stomp:"), 0, 0); loaderLayout.addWidget(checkStomp,      0, 1);
loaderLayout.addWidget(form.create_label("Technique:"),    1, 0); loaderLayout.addWidget(comboStompTech,  1, 1);
loaderLayout.addWidget(form.create_label("Stomp DLL:"),    2, 0); loaderLayout.addWidget(comboStompDll,   2, 1);
loaderLayout.addWidget(form.create_label("Unwind:"),       3, 0); loaderLayout.addWidget(checkUnwind,     3, 1);
loaderLayout.addWidget(form.create_label("Execution:"),    4, 0); loaderLayout.addWidget(checkThreadPool, 4, 1);
```

### Register in the container

```javascript
container.put("stomp_technique", comboStompTech);
```

The container key (`"stomp_technique"`) becomes the JSON key in `agentCfg` on the Go side. Combo widgets send their current text as a string value.

---

## 3. Read the Option in the Go Plugin

In `pl_build_payload.go` (or `pl_main.go` depending on repo layout), inside `BuildPayload()`:

### Parse from agentCfg

```go
myTechnique := false
if v, ok := agentCfg["stomp_technique"].(string); ok {
    myTechnique = strings.Contains(strings.ToLower(v), "my technique")
}
```

### Convert to make variable

```go
myTechFlag := "0"
if myTechnique && moduleStomp {
    myTechFlag = "1"
}
```

### Pass to make

```go
makeArgs := []string{"-C", naxRoot, target,
    "NAX_STOMP_MODE=" + stompMode,
    "NAX_EXEC_MODE=" + execMode,
    "NAX_MY_TECHNIQUE=" + myTechFlag,
    "NAX_TRANSPORT_PROFILE=" + strconv.Itoa(transportProfile),
}
```

### Add to loader rebuild sentinel

The sentinel tracks which defines were used for the last loader build. When defines change, stale `.o` files are wiped to force a full loader rebuild:

```go
currentDefines := stompMode + ":" + execMode + ":" + myTechFlag
```

### Log it

```go
buildLog(1, "module_stomp=%v  technique=%s  stomp_dll=%s", moduleStomp, myTechFlag, stompDll)
```

---

## 4. Use the Flag in C Code

### Conditional compilation pattern

```c
#if NAX_MY_TECHNIQUE

// Your technique's implementation here

#else /* !NAX_MY_TECHNIQUE */

// Basic path (existing code)

#endif
```

### Where to add conditionals

| File | What to guard |
|------|---------------|
| `src_loader/include/Common.h` | Conditional API slots in INSTANCE struct |
| `src_loader/src/Main.c` | Resolve different APIs per technique |
| `src_loader/src/Stomp.c` | Different stomping logic |
| `src_beacon/src/Bof/Stomp.c` | BOF slot init (runtime VEH or basic) |
| `src_beacon/src/Commands/Sleepmask.c` | Populate Ekko state for sleepmask BOF |
| `src_sleepmask/src/main.c` | Conditional Ekko timer chain |

### Shared structs

Both `src_beacon/include/Gate.h` and `src_sleepmask/include/Gate.h` must stay in sync. Any fields added to `NAX_EKKO_STATE` for the new technique must appear in both copies at the same offset.

If the new Ekko chain uses more timer contexts, increase `NUM_TIMER_CONTEXTS` in both Gate.h files.

---

## 5. Deployment Checklist

1. Edit `ax_config.axs` in source
2. Edit `pl_build_payload.go` in source
3. Build the Go plugin: `cd src_server/agent_nonameax && make`
4. Copy the `.axs` to the deployed directory:
   ```bash
   cp src_server/agent_nonameax/ax_config.axs \
      Server/extenders/agent_nonameax/ax_config.axs
   ```
5. Restart the Adaptix server (AXScript is loaded at startup, not hot-reloaded)
6. Verify the new dropdown appears in the build UI under Evasion > Loader

---

## File Reference

| Layer | File | What to change |
|-------|------|----------------|
| UI | `src_server/agent_nonameax/ax_config.axs` | Add combo widget, wire to container |
| Go plugin | `src_server/agent_nonameax/pl_build_payload.go` | Parse agentCfg, pass to make, update sentinel |
| Top Makefile | `Makefile` | Add `?= 0` default, add to `BEACON_TRANSPORT` and `LOADER_DEFINES` |
| Beacon Makefile | `src_beacon/Makefile` | Add `-D` flag to CFLAGS and DEBUG_CFLAGS |
| Loader | `src_loader/include/Common.h` | Conditional INSTANCE fields |
| Loader | `src_loader/src/Stomp.c` | Conditional stomp logic |
| Loader | `src_loader/src/Main.c` | Conditional API resolution |
| Beacon | `src_beacon/include/Instance.h` | Add fields to NAX_INSTANCE |
| Beacon | `src_beacon/include/Gate.h` | Add fields to NAX_EKKO_STATE |
| Beacon | `src_beacon/src/Bof/Stomp.c` | Conditional BOF slot init |
| Beacon | `src_beacon/src/Commands/Sleepmask.c` | Populate Ekko state |
| Sleepmask | `src_sleepmask/include/Gate.h` | Mirror beacon Gate.h changes |
| Sleepmask | `src_sleepmask/src/main.c` | Conditional Ekko timer chain |
