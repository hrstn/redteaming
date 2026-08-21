/*
osai-ls — OSAI Linux local-host enumeration (static, single binary).

The Linux analog of the osai-enum BOF: a single in-one-shot sweep that
gathers the recurring OSAI / AI-300 quick-win signals from Linux footholds
(as seen across the Double Helix, Pipeline Breach, Iron Crown and Synthetic
Siege labs). Built as a fully static Go binary (CGO_ENABLED=0) so it runs on
any Linux target with no runtime dependencies — upload via gopher's
`upload` and run via `run`/`shell`/`PTY`. Zero AdaptixC2 server changes.

Sections:
 1. System          hostname, /etc/os-release, kernel/arch (uname), user,
    groups, docker group, capabilities (CapEff), sudoers,
    cron jobs (the OSAI scheduled-task pivot surface).
 2. Users + SSH     per-user ~/.ssh (id_*, authorized_keys, known_hosts),
    /etc/ssh host keys + sshd_config, and /opt/<app>/deploys
    /keys (the lab-favourite deploy-key spot).
 3. AI artifacts    walk /opt /srv /app /home /var/www /etc /var/lib /root
    for model files (.pt/.pkl/.ckpt/.safetensors/.onnx/
    .gguf/...), AI-tool dirs (mlruns/ollama/n8n/langflow/
    huggingface/chroma/qdrant/weaviate/milvus/...) and AI
    config files (config.json/docker-compose.yml/.env/
    Modelfile/...).
 4. Config secrets  open small (<=64KB) text configs and scan for secret
    signatures (sk-/glpat-/AKIA/ghp_/-----BEGIN/eyJ/
    password=/connection_string/mongodb://...) with a tail
    filter + 64-byte context window. Capped.
 5. Listening ports parse /proc/net/tcp(+6), map inode->PID+comm via
    /proc/<pid>/fd, label known AI/ML service ports.
 6. Process env     walk /proc/<pid>/environ and print NAME=VALUE for vars
    matching TOKEN/KEY/SECRET/PASSWORD/VAULT/API/CONN/
    AWS/GITLAB/GITHUB/HF_... (needs
    root to read other daemons' environ — the OSAI win:
    service-account creds in running ML/GitLab/Harbor/
    Ollama daemons).

MITRE T1082/T1083/T1087/T1016/T1057/T1552/T1555; ATLAS AML-T0024/T0049.

Build:

	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
	    -o bin/osai-ls ./cmd/osai-ls
	(optionally GOARCH=arm64 for ARM Linux targets)
*/
package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const banner = "========================================"

// ─── shared signature tables (mirror the osai-enum BOF) ─────────────────────

var prefixSigs = []string{
	"sk-", "glpat-", "AKIA", "ASIA", "ghp_", "gho_", "github_pat_",
	"xoxb-", "xoxp-", "ntk_prod_", "-----BEGIN", "eyJ", "hvs.", "AIza", "xoxb",
}

var keywordSigs = []string{
	"password=", "passwd=", "Password=", "Passwd=",
	"api_key=", "apikey=", "api-key=",
	"token=", "Token=", "secret=", "Secret=",
	"Authorization: Bearer",
	"connection_string", "connectionstring",
	"mongodb://", "mongodb+srv://", "postgresql://", "postgres://",
	"mysql://", "redis://", "rediss://", "amqp://", "amqps://",
	"aws_secret", "aws_access", "huggingface_hub",
}

var envNeedles = []string{
	"TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "PASS",
	"VAULT", "CREDENTIAL", "API", "CONN", "AWS", "GITLAB",
	"GITHUB", "SLACK", "HUGGINGFACE", "HF_", "OPENAI", "ANTHROPIC",
	"AZURE", "NEXUS", "JFROG", "REGISTRY", "MIRROR", "DEPLOY",
	"SA_KEY", "SERVICE_ACCOUNT",
}

var aiPortNames = map[int]string{
	11434: "Ollama", 5000: "Flask/MLflow/Registry", 5001: "Flask/Gitea",
	5005: "MLflow", 5500: "LLM app", 7860: "Gradio",
	3000: "n8n/Gitea/Grafana/Node", 3010: "ML app", 8000: "Django/FastAPI",
	8080: "HTTP API", 8443: "HTTPS API", 8501: "TensorFlow Serving",
	8888: "Jupyter", 6006: "TensorBoard", 4040: "pydbg/ML",
	3306: "MySQL", 23306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
	7474: "Neo4j HTTP", 7687: "Neo4j Bolt", 9090: "Prometheus",
	9091: "Pushgateway", 9092: "Kafka", 5672: "RabbitMQ AMQP",
	15672: "RabbitMQ UI", 6333: "ClickHouse", 8123: "ClickHouse HTTP",
	9000: "MinIO/PHP-FPM", 4317: "OTLP gRPC", 4318: "OTLP HTTP",
	16686: "Jaeger UI", 8086: "InfluxDB", 9200: "Elasticsearch",
	5601: "Kibana", 19530: "Milvus", 27017: "MongoDB",
	5050: "Registry/Gitea-alt", 5051: "Registry",
	22: "SSH", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
}

var aiModelExts = map[string]bool{
	".pt": true, ".pth": true, ".pkl": true, ".ckpt": true, ".safetensors": true,
	".onnx": true, ".h5": true, ".model": true, ".gguf": true, ".tflite": true,
	".pb": true, ".npy": true, ".npz": true, ".joblib": true, ".keras": true,
	".bin": true, ".pmml": true, ".mlmodel": true,
}

var aiScanExts = map[string]bool{
	".env": true, ".yml": true, ".yaml": true, ".json": true, ".cfg": true,
	".ini": true, ".conf": true, ".toml": true, ".properties": true,
}

var aiScanNames = map[string]bool{
	"config.json": true, "docker-compose.yml": true, "docker-compose.yaml": true,
	"requirements.txt": true, "Dockerfile": true, "Modelfile": true,
	"models.yaml": true, "settings.json": true, "appsettings.json": true,
	"pipeline.yaml": true, "config.yaml": true, "config.yml": true,
	".env": true, "secrets.env": true, "huggingface": true,
}

var aiDirNames = map[string]bool{
	"mlruns": true, "mlflow": true, "ollama": true, "langflow": true, "n8n": true,
	"chroma": true, "qdrant": true, "weaviate": true, "milvus": true,
	"models": true, "artifacts": true, "huggingface": true, "torch": true,
	"tensorflow": true, "kubeflow": true, "airflow": true, "jupyter": true,
	"notebooks": true, "checkpoints": true, "wandb": true, "tensorboard": true,
	"datasets": true, ".ollama": true, ".cache": true, "minio": true,
	"registry": true,
}

var (
	filesScanned int
	hitsPrinted  int
)

const (
	maxFilesScanned = 300
	maxHitsPerFile  = 6
	maxHitsTotal    = 200
	scanFileCap     = 64 * 1024
)

func main() {
	fmt.Printf("\n%s\n          OSAI Linux Enumeration (osai-ls)\n%s\n", banner, banner)
	sectionSystem()
	sectionSSHKeys()
	sectionAIArtifactsAndSecrets()
	sectionListeningPorts()
	sectionProcessEnv()
	fmt.Printf("\n[*] Enumeration complete. (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
}

// ─── helpers ────────────────────────────────────────────────────────────────

func containsCI(s, needle string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(needle))
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > scanFileCap {
		// read only the first cap bytes
		buf := make([]byte, scanFileCap)
		n, _ := f.Read(buf)
		return buf[:n], nil
	}
	return os.ReadFile(path)
}

func sigTailOK(buf []byte, pos, sigLen int) bool {
	if sigLen >= 5 && buf[pos] == '-' && buf[pos+1] == '-' {
		return true // PEM header
	}
	j, cnt := pos+sigLen, 0
	for j < len(buf) && cnt < 16 {
		c := buf[j]
		if c == 0 || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
			c == '"' || c == '\'' || c == '<' || c == ',' || c == '}' ||
			c == ']' || c == ')' || c == ';' || c == '&' || c == '|' {
			break
		}
		cnt++
		j++
	}
	return cnt >= 16
}

func printSecretHit(path, sig string, buf []byte, pos int) {
	end := pos + 64
	if end > len(buf) {
		end = len(buf)
	}
	ctx := make([]byte, 0, end-pos)
	for _, c := range buf[pos:end] {
		if c >= 32 && c < 127 {
			ctx = append(ctx, c)
		} else {
			ctx = append(ctx, '.')
		}
	}
	fmt.Printf("  [secret] %s  sig=%s\n      %s\n", path, sig, string(ctx))
}

func scanFileSecrets(path string) {
	if hitsPrinted >= maxHitsTotal || filesScanned >= maxFilesScanned {
		return
	}
	filesScanned++
	buf, err := readSmall(path)
	if err != nil || len(buf) == 0 {
		return
	}
	hits := 0
	for i := 0; i < len(buf) && hits < maxHitsPerFile && hitsPrinted < maxHitsTotal; i++ {
		matched := false
		for _, sig := range prefixSigs {
			sl := len(sig)
			if i+sl <= len(buf) && string(buf[i:i+sl]) == sig && sigTailOK(buf, i, sl) {
				printSecretHit(path, sig, buf, i)
				matched = true
				break
			}
		}
		if !matched {
			for _, sig := range keywordSigs {
				sl := len(sig)
				if i+sl <= len(buf) && string(buf[i:i+sl]) == sig {
					printSecretHit(path, sig, buf, i)
					matched = true
					break
				}
			}
		}
		if matched {
			hits++
			hitsPrinted++
		}
	}
}

// ─── SECTION 1: SYSTEM ──────────────────────────────────────────────────────

var capNames = map[int]string{
	0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER",
	4: "FSETID", 5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP",
	9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_BROADCAST",
	12: "NET_ADMIN", 13: "NET_RAW", 14: "IPC_LOCK", 15: "IPC_OWNER",
	16: "SYS_MODULE", 17: "SYS_RAWIO", 18: "SYS_CHROOT", 19: "SYS_PTRACE",
	20: "SYS_PACCT", 21: "SYS_ADMIN", 22: "SYS_BOOT", 23: "SYS_NICE",
	24: "SYS_RESOURCE", 25: "SYS_TIME", 26: "SYS_TTY_CONFIG", 27: "MKNOD",
	28: "LEASE", 29: "AUDIT_WRITE", 30: "AUDIT_CONTROL", 31: "SETFCAP",
	32: "MAC_OVERRIDE", 33: "MAC_ADMIN", 34: "SYSLOG", 35: "WAKE_ALARM",
	36: "BLOCK_SUSPEND", 37: "AUDIT_READ", 38: "PERFMON", 39: "BPF",
	40: "CHECKPOINT_RESTORE",
}

func sectionSystem() {
	fmt.Printf("\n%s\n[1] SYSTEM\n%s\n", banner, banner)

	if h, err := os.Hostname(); err == nil {
		fmt.Printf("  Host   : %s\n", h)
	}
	if osrel := parseOSRelease(); osrel != "" {
		fmt.Printf("  OS     : %s\n", osrel)
	}
	if u := uname(); u != "" {
		fmt.Printf("  Kernel : %s\n", u)
	}
	fmt.Printf("  Arch   : %s\n", runtime.GOARCH)

	if u, err := user.Current(); err == nil {
		fmt.Printf("  User   : %s (uid=%s gid=%s)\n", u.Username, u.Uid, u.Gid)
		if gids, _ := u.GroupIds(); len(gids) > 0 {
			var gns []string
			for _, gid := range gids {
				if g, err := user.LookupGroupId(gid); err == nil {
					gns = append(gns, g.Name)
				}
			}
			fmt.Printf("  Groups : %s\n", strings.Join(gns, ", "))
		}
	}

	// docker group -> instant root via `docker run -v /:/host`
	if data, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "docker:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 4 && parts[3] != "" {
					fmt.Printf("  Docker : docker group members: %s (-> instant root)\n", parts[3])
				} else {
					fmt.Printf("  Docker : docker group exists (empty)\n")
				}
			}
		}
	}

	// capabilities (CapEff from /proc/self/status)
	if caps := decodeCaps(); caps != "" {
		fmt.Printf("  Caps   : %s\n", caps)
	}

	// sudoers (NOPASSWD lines are the OSAI sudo-pivot)
	sudoers()
	// cron (the OSAI scheduled-task pivot — e.g. Double Helix T11 /host-mount cron)
	cron()
}

func parseOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
			m[k] = v
		}
	}
	if m["PRETTY_NAME"] != "" {
		return m["PRETTY_NAME"]
	}
	if m["NAME"] != "" {
		return m["NAME"]
	}
	return ""
}

func uname() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	rev := func(b [65]int8) string {
		s := make([]byte, 0, 65)
		for _, c := range b {
			if c == 0 {
				break
			}
			s = append(s, byte(c))
		}
		return string(s)
	}
	return fmt.Sprintf("%s %s", rev(u.Release), rev(u.Machine))
}

func decodeCaps() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	var hex string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:\t") {
			hex = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:\t"))
			break
		}
	}
	if hex == "" {
		return ""
	}
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return ""
	}
	if v == 0 {
		return "(none)"
	}
	var names []string
	for bit := 0; bit < 41; bit++ {
		if v&(1<<bit) != 0 {
			if n, ok := capNames[bit]; ok {
				names = append(names, n)
			} else {
				names = append(names, fmt.Sprintf("CAP_%d", bit))
			}
		}
	}
	return strings.Join(names, ",")
}

func sudoers() {
	type fn func(string)
	var check fn
	check = func(p string) {
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Defaults") {
				continue
			}
			if strings.HasPrefix(l, "@includedir ") {
				dir := strings.TrimSpace(strings.TrimPrefix(l, "@includedir "))
				matches, _ := filepath.Glob(filepath.Join(dir, "*"))
				for _, m := range matches {
					check(m)
				}
				continue
			}
			if strings.HasPrefix(l, "@include ") {
				check(strings.TrimSpace(strings.TrimPrefix(l, "@include ")))
				continue
			}
			if strings.Contains(l, "NOPASSWD") || strings.Contains(l, " ALL") {
				fmt.Printf("  [sudoers] %s: %s\n", p, l)
			}
		}
	}
	check("/etc/sudoers")
	matches, _ := filepath.Glob("/etc/sudoers.d/*")
	for _, m := range matches {
		check(m)
	}
}

func cron() {
	var cronFiles []string
	cronFiles = append(cronFiles, "/etc/crontab")
	if m, _ := filepath.Glob("/etc/cron.d/*"); m != nil {
		cronFiles = append(cronFiles, m...)
	}
	if m, _ := filepath.Glob("/var/spool/cron/crontabs/*"); m != nil {
		cronFiles = append(cronFiles, m...)
	}
	if m, _ := filepath.Glob("/var/spool/cron/*"); m != nil {
		cronFiles = append(cronFiles, m...)
	}
	any := false
	for _, p := range cronFiles {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if !any {
				fmt.Printf("  -- cron --\n")
				any = true
			}
			fmt.Printf("  [cron] %s: %s\n", p, l)
		}
	}
}

// ─── SECTION 2: USERS + SSH KEYS ────────────────────────────────────────────

func sectionSSHKeys() {
	fmt.Printf("\n%s\n[2] USERS + SSH KEYS\n%s\n", banner, banner)

	// home dirs from /etc/passwd
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 7 {
				continue
			}
			home := parts[5]
			shell := parts[6]
			if home == "" || home == "/" {
				continue
			}
			// list ~/.ssh
			sshDir := filepath.Join(home, ".ssh")
			listSSHDir(sshDir, "ssh")
			_ = shell
		}
	}
	// /etc/ssh host keys + sshd_config
	listSSHDir("/etc/ssh", "ssh-sys")

	// /opt/*/deploys/keys and /opt/*/keys (the lab-favourite deploy-key spot)
	if entries, err := os.ReadDir("/opt"); err == nil {
		for _, e := range entries {
			for _, sub := range []string{"deploys/keys", "keys", ".ssh"} {
				listSSHDir(filepath.Join("/opt", e.Name(), sub), "deploy-key")
			}
		}
	}
}

func listSSHDir(dir, label string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fmt.Printf("  [%s] %s\n", label, full)
	}
}

// ─── SECTION 3+4: AI ARTIFACTS + CONFIG SECRETS ─────────────────────────────

var walkRoots = []string{
	"/opt", "/srv", "/app", "/home", "/var/www", "/etc", "/var/lib", "/root",
}

var skipDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
	"/var/lib/docker/containers": true, "/var/lib/docker/overlay2": true,
}

func sectionAIArtifactsAndSecrets() {
	fmt.Printf("\n%s\n[3] AI/ML ARTIFACTS & CONFIG SECRETS\n%s\n", banner, banner)
	for _, root := range walkRoots {
		filepath.WalkDir(root, walkAI)
	}
	fmt.Printf("  -- scanned %d cfg file(s), %d secret hit(s)\n", filesScanned, hitsPrinted)
}

func walkAI(p string, d fs.DirEntry, err error) error {
	if err != nil {
		return fs.SkipDir
	}
	if filesScanned >= maxFilesScanned {
		return fs.SkipDir
	}
	if d.IsDir() {
		name := d.Name()
		if skipDirs[p] {
			return fs.SkipDir
		}
		// don't recurse into huge/virtual subtrees
		if name == "node_modules" || name == ".git" || name == "site-packages" ||
			name == "dist-packages" || name == "vendor" || name == "__pycache__" {
			return fs.SkipDir
		}
		if aiDirNames[name] {
			fmt.Printf("  [ai-dir] %s\n", p)
		}
		return nil
	}
	// file
	name := d.Name()
	ext := strings.ToLower(filepath.Ext(name))
	if aiModelExts[ext] {
		fmt.Printf("  [model]  %s\n", p)
		return nil
	}
	if aiScanExts[ext] || aiScanNames[name] {
		fmt.Printf("  [cfg]    %s\n", p)
		scanFileSecrets(p)
	}
	return nil
}

// ─── SECTION 5: LISTENING PORTS ─────────────────────────────────────────────

type listener struct {
	local string
	port  int
	inode uint64
	v6    bool
}

func sectionListeningPorts() {
	fmt.Printf("\n%s\n[4] LISTENING TCP PORTS\n%s\n", banner, banner)
	inodeMap := buildInodeMap()
	var listeners []listener
	parseTCP("/proc/net/tcp", false, &listeners)
	parseTCP("/proc/net/tcp6", true, &listeners)
	if len(listeners) == 0 {
		fmt.Printf("  (no listening TCP sockets found)\n")
		return
	}
	fmt.Printf("  %-26s %-7s  %s\n", "Address:Port", "PID", "Process / Service")
	fmt.Printf("  %-26s %-7s  %s\n", "------------", "-----", "---------------")
	for _, l := range listeners {
		svc := aiPortNames[l.port]
		pi, ok := inodeMap[l.inode]
		pid, comm := "-", "<unknown>"
		if ok {
			pid, comm = pi.pid, pi.comm
		}
		ap := fmt.Sprintf("%s:%d", l.local, l.port)
		if svc != "" {
			fmt.Printf("  %-26s %-7s  %s  [%s]\n", ap, pid, comm, svc)
		} else {
			fmt.Printf("  %-26s %-7s  %s\n", ap, pid, comm)
		}
	}
}

func parseTCP(path string, v6 bool, out *[]listener) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 65536), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		st := fields[3]
		inodeS := fields[9]
		if st != "0A" { // 0A = TCP_LISTEN
			continue
		}
		addr, port := parseAddr(local, v6)
		if port == 0 {
			continue
		}
		inode, _ := strconv.ParseUint(inodeS, 10, 64)
		*out = append(*out, listener{local: addr, port: port, inode: inode, v6: v6})
	}
}

func parseAddr(s string, v6 bool) (string, int) {
	colon := strings.Index(s, ":")
	if colon < 0 {
		return s, 0
	}
	hexAddr := s[:colon]
	hexPort := s[colon+1:]
	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return s, 0
	}
	if v6 {
		// 32 hex chars = 4 little-endian u32 words
		var ip [16]byte
		for w := 0; w < 4; w++ {
			if len(hexAddr) < (w+1)*8 {
				break
			}
			v, err := strconv.ParseUint(hexAddr[w*8:w*8+8], 16, 32)
			if err != nil {
				return s, int(port)
			}
			ip[w*4+0] = byte(v & 0xff)
			ip[w*4+1] = byte((v >> 8) & 0xff)
			ip[w*4+2] = byte((v >> 16) & 0xff)
			ip[w*4+3] = byte((v >> 24) & 0xff)
		}
		return net.IP(ip[:]).String(), int(port)
	}
	// v4: 8 hex chars little-endian
	if len(hexAddr) >= 8 {
		v, err := strconv.ParseUint(hexAddr[:8], 16, 32)
		if err == nil {
			ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
			return ip.String(), int(port)
		}
	}
	return s, int(port)
}

// map socket inode -> owning process info
type procInfo struct {
	pid  string
	comm string
}

func buildInodeMap() map[uint64]procInfo {
	m := map[uint64]procInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		comm := pid
		if b, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			// link = "socket:[<inode>]"
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				in := link[8 : len(link)-1]
				if inode, err := strconv.ParseUint(in, 10, 64); err == nil {
					if _, exists := m[inode]; !exists {
						m[inode] = procInfo{pid: pid, comm: comm}
					}
				}
			}
		}
	}
	return m
}

// ─── SECTION 6: PROCESS ENV SECRETS ─────────────────────────────────────────

func sectionProcessEnv() {
	fmt.Printf("\n%s\n[5] PROCESS ENV SECRETS (/proc/*/environ)\n%s\n", banner, banner)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Printf("  [!] cannot read /proc\n")
		return
	}
	total := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + pid + "/environ")
		if err != nil {
			continue // EACCES if not root and not our process
		}
		comm := pid
		if b, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		for _, kv := range strings.Split(string(data), "\x00") {
			i := strings.Index(kv, "=")
			if i <= 0 {
				continue
			}
			name := kv[:i]
			val := kv[i+1:]
			if !envInteresting(name) {
				continue
			}
			if len(val) > 260 {
				val = val[:260]
			}
			fmt.Printf("  [env] %6s %-16s %s=%s\n", pid, comm, name, val)
			total++
			if total >= 200 {
				fmt.Printf("  -- hit cap (200), stopping --\n")
				return
			}
		}
	}
	if total == 0 {
		fmt.Printf("  (none — need root to read other daemons' /proc/*/environ; own env shown above if any)\n")
	}
}

func envInteresting(name string) bool {
	up := strings.ToUpper(name)
	for _, n := range envNeedles {
		if strings.Contains(up, n) {
			return true
		}
	}
	return false
}
