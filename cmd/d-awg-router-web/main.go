package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	port = "8765"
	host = "127.0.0.1"
)

var (
	homeDir    string
	awgDir     string
	configsDir string
	cacheDir   string
	routesDir  string
	stateDir   string

	repoCIDRAPI = "https://api.github.com/repos/RockBlack-VPN/ip-address/contents/Global"
	repoRawFmt  = "https://raw.githubusercontent.com/RockBlack-VPN/ip-address/main/Global/%s/%s"
	awgBin      = "/usr/local/bin/awg"
	awgGo       = "/usr/local/bin/amneziawg-go"
)

func init() {
	var err error
	homeDir, err = os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	awgDir = filepath.Join(homeDir, ".d-awg-router")
	configsDir = filepath.Join(awgDir, "configs")
	cacheDir = filepath.Join(awgDir, "cache")
	routesDir = filepath.Join(awgDir, "routes")
	stateDir = filepath.Join(awgDir, "state")
	for _, d := range []string{configsDir, cacheDir, routesDir, stateDir} {
		os.MkdirAll(d, 0755)
	}
}

// === WireGuard Config ===

type AWGConfig struct {
	Address    string
	PrivateKey string
	DNS        string
	Jc, Jmin, Jmax int
	S1, S2     int
	H1, H2, H3, H4 int
	PublicKey  string
	AllowedIPs string
	Endpoint   string
	PKA        int
}

func parseWGConfig(data string) (*AWGConfig, error) {
	cfg := &AWGConfig{PKA: 27}
	re := func(key string) (string, bool) {
		m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*=\s*(.+)$`).FindStringSubmatch(data)
		if len(m) >= 2 {
			return strings.TrimSpace(m[1]), true
		}
		return "", false
	}
	for _, kv := range []struct{ k string; v *string }{
		{"Address", &cfg.Address}, {"PrivateKey", &cfg.PrivateKey}, {"DNS", &cfg.DNS},
		{"PublicKey", &cfg.PublicKey}, {"AllowedIPs", &cfg.AllowedIPs}, {"Endpoint", &cfg.Endpoint},
	} {
		if v, ok := re(kv.k); ok {
			*kv.v = v
		}
	}
	for _, kv := range []struct{ k string; v *int }{
		{"Jc", &cfg.Jc}, {"Jmin", &cfg.Jmin}, {"Jmax", &cfg.Jmax},
		{"S1", &cfg.S1}, {"S2", &cfg.S2},
		{"H1", &cfg.H1}, {"H2", &cfg.H2}, {"H3", &cfg.H3}, {"H4", &cfg.H4},
		{"PersistentKeepalive", &cfg.PKA},
	} {
		if v, ok := re(kv.k); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*kv.v = n
			}
		}
	}
	if cfg.PrivateKey == "" || cfg.Endpoint == "" || cfg.PublicKey == "" {
		return nil, fmt.Errorf("неполный конфиг: нужны PrivateKey, Endpoint и PublicKey")
	}
	return cfg, nil
}

func (c *AWGConfig) Save(path string) error {
	var buf bytes.Buffer
	buf.WriteString("[Interface]\n")
	buf.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey))
	if c.Address != "" {
		buf.WriteString(fmt.Sprintf("Address = %s\n", c.Address))
	}
	if c.DNS != "" {
		buf.WriteString(fmt.Sprintf("DNS = %s\n", c.DNS))
	}
	buf.WriteString(fmt.Sprintf("Jc = %d\n", c.Jc))
	buf.WriteString(fmt.Sprintf("Jmin = %d\n", c.Jmin))
	buf.WriteString(fmt.Sprintf("Jmax = %d\n", c.Jmax))
	buf.WriteString(fmt.Sprintf("S1 = %d\n", c.S1))
	buf.WriteString(fmt.Sprintf("S2 = %d\n", c.S2))
	buf.WriteString(fmt.Sprintf("H1 = %d\n", c.H1))
	buf.WriteString(fmt.Sprintf("H2 = %d\n", c.H2))
	buf.WriteString(fmt.Sprintf("H3 = %d\n", c.H3))
	buf.WriteString(fmt.Sprintf("H4 = %d\n", c.H4))
	buf.WriteString("\n[Peer]\n")
	buf.WriteString(fmt.Sprintf("PublicKey = %s\n", c.PublicKey))
	buf.WriteString(fmt.Sprintf("AllowedIPs = %s\n", c.AllowedIPs))
	buf.WriteString(fmt.Sprintf("Endpoint = %s\n", c.Endpoint))
	buf.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", c.PKA))
	return os.WriteFile(path, buf.Bytes(), 0600)
}

func (c *AWGConfig) SaveAWGOnly(path string) {
	var buf bytes.Buffer
	buf.WriteString("[Interface]\n")
	buf.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey))
	buf.WriteString(fmt.Sprintf("Jc = %d\n", c.Jc))
	buf.WriteString(fmt.Sprintf("Jmin = %d\n", c.Jmin))
	buf.WriteString(fmt.Sprintf("Jmax = %d\n", c.Jmax))
	buf.WriteString(fmt.Sprintf("S1 = %d\n", c.S1))
	buf.WriteString(fmt.Sprintf("S2 = %d\n", c.S2))
	buf.WriteString(fmt.Sprintf("H1 = %d\n", c.H1))
	buf.WriteString(fmt.Sprintf("H2 = %d\n", c.H2))
	buf.WriteString(fmt.Sprintf("H3 = %d\n", c.H3))
	buf.WriteString(fmt.Sprintf("H4 = %d\n", c.H4))
	buf.WriteString("\n[Peer]\n")
	buf.WriteString(fmt.Sprintf("PublicKey = %s\n", c.PublicKey))
	buf.WriteString(fmt.Sprintf("AllowedIPs = %s\n", c.AllowedIPs))
	buf.WriteString(fmt.Sprintf("Endpoint = %s\n", c.Endpoint))
	buf.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", c.PKA))
	os.WriteFile(path, buf.Bytes(), 0600)
}

func loadConfig(name string) (*AWGConfig, error) {
	data, err := os.ReadFile(filepath.Join(configsDir, name))
	if err != nil {
		return nil, err
	}
	return parseWGConfig(string(data))
}

func listConfigs() []string {
	entries, _ := os.ReadDir(configsDir)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func getCurrentConfig() *AWGConfig {
	for _, name := range listConfigs() {
		if cfg, err := loadConfig(name); err == nil && cfg.Address != "" {
			return cfg
		}
	}
	return nil
}

// === CIDR Services ===

type ServiceInfo struct {
	Name string
	Path string
}

func fetchServiceList() ([]ServiceInfo, error) {
	req, _ := http.NewRequest("GET", repoCIDRAPI, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var items []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	}
	json.Unmarshal(body, &items)
	var svc []ServiceInfo
	for _, it := range items {
		if it.Type == "dir" {
			n := strings.TrimSpace(it.Name)
			if n != "" && n != ".." {
				svc = append(svc, ServiceInfo{Name: n, Path: it.Path})
			}
		}
	}
	return svc, nil
}

func fetchServiceCIDR(serviceName string) (string, error) {
	path := strings.ReplaceAll(serviceName, " ", "%20")
	// Пробуем разные имена .bat файлов: telegram.bat, <service>.bat, service.bat
	candidates := []string{
		"telegram.bat",
		strings.ReplaceAll(serviceName, " ", "_") + ".bat",
		strings.ReplaceAll(serviceName, " ", "") + ".bat",
		"service.bat",
	}
	for _, bat := range candidates {
		url := fmt.Sprintf(repoRawFmt, path, bat)
		if data, err := fetchURL(url); err == nil && len(data) > 0 {
			return parseBatCIDR(data), nil
		}
	}
	// Ищем в папке сервиса
	dirURL := fmt.Sprintf("https://api.github.com/repos/RockBlack-VPN/ip-address/contents/Global/%s", path)
	if files, err := fetchDir(dirURL); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f, ".bat") {
				url := fmt.Sprintf(repoRawFmt, path, f)
				if data, err := fetchURL(url); err == nil && len(data) > 0 {
					return parseBatCIDR(data), nil
				}
			}
		}
	}
	return "", fmt.Errorf("CIDR не найден для %s", serviceName)
}

func fetchDir(url string) ([]string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var items []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	json.Unmarshal(body, &items)
	var names []string
	for _, it := range items {
		if it.Type == "file" {
			names = append(names, it.Name)
		}
	}
	return names, nil
}

func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func parseBatCIDR(data string) string {
	var cidrs []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 6 || parts[0] != "route" || parts[1] != "add" || parts[3] != "mask" {
			continue
		}
		prefix := maskToPrefix(parts[4])
		if prefix > 0 {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", parts[2], prefix))
		}
	}
	return strings.Join(cidrs, " ")
}

func maskToPrefix(mask string) int {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return 0
	}
	n := 0
	for _, p := range parts {
		v, _ := strconv.Atoi(p)
		switch {
		case v == 255:
			n += 8
		case v == 254:
			n += 7
		case v == 252:
			n += 6
		case v == 248:
			n += 5
		case v == 240:
			n += 4
		case v == 224:
			n += 3
		case v == 192:
			n += 2
		case v == 128:
			n += 1
		}
	}
	return n
}

// === Cache ===

func cachePath(name string) string { return filepath.Join(cacheDir, name+".cidr") }

func loadCIDRCache(name string) string {
	d, _ := os.ReadFile(cachePath(name))
	return strings.TrimSpace(string(d))
}

func saveCIDRCache(name, data string) {
	os.WriteFile(cachePath(name), []byte(data), 0644)
}

func loadAllCIDRs() string {
	var all []string
	for _, s := range loadRoutes() {
		if d := loadCIDRCache(s); d != "" {
			all = append(all, d)
		}
	}
	return strings.Join(all, " ")
}

// === Routes ===

func loadRoutes() []string {
	entries, _ := os.ReadDir(routesDir)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func setRoute(name string, active bool) {
	p := filepath.Join(routesDir, name)
	if active {
		os.WriteFile(p, []byte{}, 0644)
	} else {
		os.Remove(p)
	}
}

// === Interface ===

func awgIP() string {
	if cfg := getCurrentConfig(); cfg != nil {
		return strings.Split(cfg.Address, "/")[0]
	}
	return ""
}

func findAWGInterface() string {
	out, err := sudo(awgBin, "show")
	if err != nil || out == "" {
		return ""
	}
	// awg show без аргументов показывает первый найденный интерфейс
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "interface: utun") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface: "))
		}
	}
	return ""
}

func isAlive(iface string) bool {
	out, _ := sudo(awgBin, "show", iface)
	return len(out) > 0
}

func pgrepAWG(iface string) []byte {
	out, _ := exec.Command("pgrep", "-f", "amneziawg-go.*"+iface).Output()
	return out
}

// === Sudo ===

// // //
func sudo(args ...string) (string, error) {
	// Используем -n (non-interactive) для фоновых вызовов
	args2 := append([]string{"-n"}, args...)
	cmd := exec.Command("sudo", args2...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir, "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if stderr.Len() > 0 && err != nil {
		out += "\n[stderr]\n" + stderr.String()
	}
	return out, err
}

// === Commands ===

func countCIDRs(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Fields(s))
}

func updateRoutes(iface, cidrs string) {
	for _, c := range strings.Fields(cidrs) {
		sudo("route", "-q", "-n", "add", c, "-interface", iface)
	}
}

func removeAllRoutes() {
	iface := findAWGInterface()
	if iface == "" {
		return
	}
	for _, s := range loadRoutes() {
		for _, c := range strings.Fields(loadCIDRCache(s)) {
			sudo("route", "-q", "-n", "delete", strings.Split(c, "/")[0])
		}
	}
}

func cmdUp() string {
	cfg := getCurrentConfig()
	if cfg == nil || cfg.Address == "" {
		return "[ERROR] Нет загруженного конфига с Address. Загрузите WireGuard конфиг."
	}
	ip := strings.Split(cfg.Address, "/")[0]
	iface := findAWGInterface()
	if iface != "" && isAlive(iface) {
		out := fmt.Sprintf("[✓] Найден активный интерфейс %s\n", iface)
		if routes := loadAllCIDRs(); routes != "" {
			updateRoutes(iface, routes)
			out += "[✓] Маршруты обновлены\n"
		} else {
			out += "[!] Нет активных сервисов\n"
		}
		so, _ := sudo(awgBin, "show", iface)
		out += so
		return out
	}
	// Свободный utun
	var freeDev string
	for i := 6; i <= 15; i++ {
		dev := fmt.Sprintf("utun%d", i)
		info, _ := exec.Command("ifconfig", dev).Output()
		s := string(info)
		if s == "" || (strings.Contains(s, "UP,POINTOPOINT,RUNNING") && !strings.Contains(s, "inet ")) {
			freeDev = dev
			break
		}
	}
	if freeDev == "" {
		return "[ERROR] Нет свободных utun"
	}
	iface = freeDev

	awgConf := filepath.Join(configsDir, "._awg_setconf")
	cfg.SaveAWGOnly(awgConf)
	defer os.Remove(awgConf)

	// Запускаем amneziawg-go в фоне
	startCmd := exec.Command("sudo", "-n", awgGo, iface)
	startCmd.Stdout = nil
	startCmd.Stderr = nil
	startCmd.Start()
	time.Sleep(2 * time.Second)
	if !isAlive(iface) {
		log, _ := os.ReadFile(fmt.Sprintf("/tmp/awg-%s.log", iface))
		errMsg := "[ERROR] amneziawg-go не запустился"
		if len(log) > 0 {
			errMsg += "\n[log]\n" + string(log)
		}
		return errMsg
	}
	sudo("/sbin/ifconfig", iface, ip, ip)
	sudo(awgBin, "setconf", iface, awgConf)
	routes := loadAllCIDRs()
	if routes != "" {
		updateRoutes(iface, routes)
	}
	saveState(iface, ip)
	so, _ := sudo(awgBin, "show", iface)
	out := fmt.Sprintf("[✓] AmneziaWG поднят на %s\n\n%s", iface, so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] Маршруты добавлены (%d подсетей)\n", countCIDRs(routes))
	}
	return out
}

type State struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}
func statePath() string { return filepath.Join(stateDir, "current") }
func saveState(iface, ip string) { d, _ := json.Marshal(State{iface, ip}); os.WriteFile(statePath(), d, 0644) }
func clearState() { os.Remove(statePath()) }

func cmdDown() string {
	iface := findAWGInterface()
	if iface == "" {
		return "[!] Активный интерфейс не найден"
	}
	removeAllRoutes()
	pids := pgrepAWG(iface)
	if len(pids) > 0 {
		sudo("kill", "-TERM", strings.TrimSpace(string(pids)))
		time.Sleep(1 * time.Second)
		sudo("kill", "-9", strings.TrimSpace(string(pids)))
	}
	sudo("rm", "-f", fmt.Sprintf("/var/run/amneziawg/%s.sock", iface))
	clearState()
	return fmt.Sprintf("[✓] %s опущен", iface)
}

func cmdRestart() string {
	out := cmdDown()
	if strings.Contains(out, "[ERROR]") {
		return out
	}
	time.Sleep(1 * time.Second)
	return out + "\n" + cmdUp()
}

func cmdShow() string {
	iface := findAWGInterface()
	if iface == "" {
		return "[!] AmneziaWG не активен"
	}
	var out string
	out += fmt.Sprintf("=== AmneziaWG (%s) ===\n", iface)
	if so, err := sudo(awgBin, "show", iface); err == nil {
		out += so
	}
	if io, _ := exec.Command("ifconfig", iface).Output(); len(io) > 0 {
		out += "\n=== Интерфейс ===\n"
		for _, line := range strings.Split(string(io), "\n") {
			if strings.HasPrefix(line, iface) || strings.Contains(line, "inet ") {
				out += line + "\n"
			}
		}
	}
	out += "\n=== Активные маршруты ===\n"
	routes := loadRoutes()
	if len(routes) == 0 {
		out += "  (нет выбранных сервисов)\n"
	} else {
		routeOut, _ := exec.Command("netstat", "-rn", "-f", "inet").Output()
		rt := strings.Split(string(routeOut), "\n")
		for _, s := range routes {
			cidrData := loadCIDRCache(s)
			cnt := countCIDRs(cidrData)
			ok := 0
			for _, c := range strings.Fields(cidrData) {
				net := strings.Split(c, "/")[0]
				for _, r := range rt {
					if strings.Contains(r, iface) && strings.Contains(r, strings.Split(net, ".")[0]+"."+strings.Split(net, ".")[1]) {
						ok++
						break
					}
				}
			}
			sym := "[✓]"
			if ok < cnt {
				sym = "[✗]"
			}
			out += fmt.Sprintf("  %s %s (%d/%d)\n", sym, s, ok, cnt)
		}
	}
	return out
}

func cmdRoutesForce() string {
	iface := findAWGInterface()
	if iface == "" {
		return "[!] AmneziaWG не активен. Запустите UP сначала."
	}
	routes := loadAllCIDRs()
	if routes == "" {
		return "[!] Нет активных сервисов"
	}
	updateRoutes(iface, routes)
	return fmt.Sprintf("[✓] Маршруты обновлены на %s (%d подсетей)", iface, countCIDRs(routes))
}

func updateAllCIDRs() string {
	services, err := fetchServiceList()
	if err != nil {
		return "[WARN] GitHub недоступен, использую кэш"
	}
	active := loadRoutes()
	am := make(map[string]bool)
	for _, s := range active {
		am[s] = true
	}
	var out string
	for _, s := range services {
		if !am[s.Name] {
			continue
		}
		cidrData, err := fetchServiceCIDR(s.Name)
		if err != nil {
			if cached := loadCIDRCache(s.Name); cached != "" {
				out += fmt.Sprintf("[✓] %s: из кэша (%d)\n", s.Name, countCIDRs(cached))
			}
			continue
		}
		saveCIDRCache(s.Name, cidrData)
		out += fmt.Sprintf("[✓] %s: загружено %d подсетей\n", s.Name, countCIDRs(cidrData))
	}
	return out
}

// === HTTP Server ===

var pageHTML string

func initPage() {
	pageHTML = `<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>d-awg-router</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
.container{max-width:900px;margin:0 auto}
h1{font-size:1.5em;margin-bottom:4px;color:#58a6ff}
.sub{color:#8b949e;font-size:13px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;color:#8b949e;text-transform:uppercase;margin-bottom:12px}
.btn{padding:8px 16px;border:none;border-radius:6px;font-size:13px;cursor:pointer;color:#fff;font-weight:500;display:inline-block}
.btn-up{background:#238636}
.btn-down{background:#da3633}
.btn-restart{background:#1f6feb}
.btn-show{background:#6e7681}
.btn-routes{background:#8957e5}
.btn-save{background:#1f6feb}
.btn:hover{filter:brightness(1.2)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.flex{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.mt{margin-top:12px}
pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:500px;overflow-y:auto}
textarea.config{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;color:#c9d1d9;font-family:monospace;font-size:12px;min-height:180px;resize:vertical}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px}
label{display:block;padding:4px 0;cursor:pointer;font-size:13px}
label input{margin-right:6px}
.error{color:#f85149}
.success{color:#3fb950}
</style></head>
<body>
<div class="container">
<h1>d-awg-router-web</h1>
<p class="sub">AmneziaWG VPN Router</p>

<div class="card">
<h2>VPN</h2>
<form method="post" class="flex" onsubmit="return confirmAction(event)">
<button class="btn btn-up" name="cmd" value="up">UP</button>
<button class="btn btn-down" name="cmd" value="down">DOWN</button>
<button class="btn btn-restart" name="cmd" value="restart">RESTART</button>
<button class="btn btn-show" name="cmd" value="show">SHOW</button>
<button class="btn btn-routes" name="cmd" value="routes-force">ROUTES</button>
</form>
</div>

<div class="card">
<h2>WireGuard Config</h2>
<form method="post">
<textarea class="config" name="config" placeholder="[Interface]&#10;Address = 10.72.171.186/32&#10;PrivateKey = ...">__CONFIG_TEXT__</textarea>
<div class="flex mt"><button class="btn btn-save" name="cmd" value="save-config">Save Config</button></div>
</form>
__CONFIG_SAVED__</div>

<div class="card">
<h2>Services</h2>
<form method="post">
<div class="grid">__SERVICES__</div>
<div class="flex mt">
<button class="btn btn-save" name="cmd" value="save-services">Save Selection</button>
<button class="btn btn-routes" name="cmd" value="update-cidr">Update CIDR</button>
</div>
</form>
</div>

<div class="card">
<h2>Output</h2>
<pre>__OUTPUT__</pre>
</div>
</div>
<script>
function confirmAction(e) {
  var v = e.submitter.value;
  if (v==="down"||v==="restart") return confirm(v==="down"?"Down VPN?":"Restart VPN?");
  return true;
}
</script>
</body></html>`
}

func render(w http.ResponseWriter, replacements map[string]string) {
	p := pageHTML
	for k, v := range replacements {
		p = strings.ReplaceAll(p, k, v)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, p)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		showPage(w, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.ParseForm()
	cmd := r.FormValue("cmd")

	switch cmd {
	case "save-config":
		text := r.FormValue("config")
		if text == "" {
			showPage(w, `<span class="error">Empty config</span>`)
			return
		}
		cfg, err := parseWGConfig(text)
		if err != nil {
			showPage(w, fmt.Sprintf(`<span class="error">%v</span>`, err))
			return
		}
		if err := cfg.Save(filepath.Join(configsDir, "telegram.conf")); err != nil {
			showPage(w, fmt.Sprintf(`<span class="error">Save error: %v</span>`, err))
			return
		}
		showPage(w, `<span class="success">Config saved to telegram.conf</span>`)
	case "save-services":
		// Запоминаем старые сервисы до очистки
		oldServices := loadRoutes()

		// Чистим routes/ файлы
		entries, _ := os.ReadDir(routesDir)
		for _, e := range entries {
			if !e.IsDir() {
				os.Remove(filepath.Join(routesDir, e.Name()))
			}
		}

		// Добавляем новые
		for _, v := range r.Form["service"] {
			if v != "" {
				setRoute(v, true)
			}
		}

		// Обновляем CIDR для новых сервисов
		out := updateAllCIDRs()

		// Переустанавливаем маршруты, если VPN активен
		if iface := findAWGInterface(); iface != "" {
			// Удаляем старые маршруты
			for _, s := range oldServices {
				for _, c := range strings.Fields(loadCIDRCache(s)) {
					sudo("route", "-q", "-n", "delete", strings.Split(c, "/")[0])
				}
			}
			// Добавляем новые
			if routes := loadAllCIDRs(); routes != "" {
				updateRoutes(iface, routes)
				out += fmt.Sprintf("\n[✓] Маршруты обновлены (%d подсетей)", countCIDRs(routes))
			}
		}

		showPage(w, `<span class="success">Saved.</span><br>`+out)
	case "update-cidr":
		showPage(w, updateAllCIDRs())
	case "up":
		showPage(w, cmdUp())
	case "down":
		showPage(w, cmdDown())
	case "restart":
		showPage(w, cmdRestart())
	case "show":
		showPage(w, cmdShow())
	case "routes-force":
		showPage(w, cmdRoutesForce())
	default:
		showPage(w, `<span class="error">Unknown command</span>`)
	}
}

func showPage(w http.ResponseWriter, output string) {
	repl := map[string]string{
		"__OUTPUT__":      output,
		"__CONFIG_SAVED__": "",
		"__CONFIG_TEXT__": "",
	}
	// Заполняем конфиг
	if cfg := getCurrentConfig(); cfg != nil {
		var buf bytes.Buffer
		buf.WriteString(fmt.Sprintf("[Interface]\nAddress = %s\nPrivateKey = %s\n", cfg.Address, cfg.PrivateKey))
		if cfg.DNS != "" {
			buf.WriteString(fmt.Sprintf("DNS = %s\n", cfg.DNS))
		}
		buf.WriteString(fmt.Sprintf("Jc = %d\nJmin = %d\nJmax = %d\n", cfg.Jc, cfg.Jmin, cfg.Jmax))
		buf.WriteString(fmt.Sprintf("S1 = %d\nS2 = %d\n", cfg.S1, cfg.S2))
		buf.WriteString(fmt.Sprintf("H1 = %d\nH2 = %d\nH3 = %d\nH4 = %d\n", cfg.H1, cfg.H2, cfg.H3, cfg.H4))
		buf.WriteString(fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n", cfg.PublicKey, cfg.AllowedIPs, cfg.Endpoint, cfg.PKA))
		repl["__CONFIG_TEXT__"] = buf.String()
	}

	// Заполняем сервисы
	services, _ := fetchServiceList()
	active := loadRoutes()
	am := make(map[string]bool)
	for _, s := range active {
		am[s] = true
	}
	var svcHTML strings.Builder
	if len(services) == 0 {
		svcHTML.WriteString(`<span class="error">GitHub недоступен</span>`)
	} else {
		for _, s := range services {
			checked := ""
			if am[s.Name] {
				checked = " checked"
			}
			svcHTML.WriteString(fmt.Sprintf(`<label><input type="checkbox" name="service" value="%s"%s>%s</label>`, htmlEsc(s.Name), checked, htmlEsc(s.Name)))
		}
	}
	repl["__SERVICES__"] = svcHTML.String()

	render(w, repl)
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func main() {
	initPage()
	http.HandleFunc("/", handler)
	addr := fmt.Sprintf("%s:%s", host, port)
	println("d-awg-router-web on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
