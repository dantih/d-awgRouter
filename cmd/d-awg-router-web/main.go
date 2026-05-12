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
	activeCfg  string // имя активного конфига
	langName   string // текущий язык "en" или "ru"
	lang       LangMap

	repoCIDRAPI = "https://api.github.com/repos/RockBlack-VPN/ip-address/contents/Global"
	repoRawFmt  = "https://raw.githubusercontent.com/RockBlack-VPN/ip-address/main/Global/%s/%s"
	wgBin       = "/opt/homebrew/bin/wg"
	awgBin      = "/usr/local/bin/awg"
	awgGo       = "/usr/local/bin/amneziawg-go"
)

func tr(key string, args ...interface{}) string {
	if v, ok := lang[key]; ok {
		if len(args) > 0 {
			return fmt.Sprintf(v, args...)
		}
		return v
	}
	return key
}

func initBins() {
	for _, b := range []struct {
		dst *string
		names []string
	}{
		{&wgBin, []string{"wg", "/opt/homebrew/bin/wg"}},
		{&awgBin, []string{"awg"}},
		{&awgGo, []string{"amneziawg-go"}},
	} {
		for _, n := range b.names {
			if p, err := exec.LookPath(n); err == nil {
				*b.dst = p
				break
			}
		}
	}
}

func init() {
	initBins()
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
	// Загрузка языка
	langName = "en"
	if data, err := os.ReadFile(filepath.Join(awgDir, "lang")); err == nil {
		l := strings.TrimSpace(string(data))
		if _, ok := langData[l]; ok {
			langName = l
		}
	}
	lang = langData[langName]
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
	IsWireGuard bool
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
	_, hasJc := re("Jc")
	cfg.IsWireGuard = !hasJc
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
	if !c.IsWireGuard {
		buf.WriteString(fmt.Sprintf("Jc = %d\n", c.Jc))
		buf.WriteString(fmt.Sprintf("Jmin = %d\n", c.Jmin))
		buf.WriteString(fmt.Sprintf("Jmax = %d\n", c.Jmax))
		buf.WriteString(fmt.Sprintf("S1 = %d\n", c.S1))
		buf.WriteString(fmt.Sprintf("S2 = %d\n", c.S2))
		buf.WriteString(fmt.Sprintf("H1 = %d\n", c.H1))
		buf.WriteString(fmt.Sprintf("H2 = %d\n", c.H2))
		buf.WriteString(fmt.Sprintf("H3 = %d\n", c.H3))
		buf.WriteString(fmt.Sprintf("H4 = %d\n", c.H4))
	}
	buf.WriteString("\n[Peer]\n")
	buf.WriteString(fmt.Sprintf("PublicKey = %s\n", c.PublicKey))
	buf.WriteString(fmt.Sprintf("AllowedIPs = %s\n", c.AllowedIPs))
	buf.WriteString(fmt.Sprintf("Endpoint = %s\n", c.Endpoint))
	buf.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", c.PKA))
	return os.WriteFile(path, buf.Bytes(), 0600)
}

func (c *AWGConfig) SaveKernelConfig(path string) {
	var buf bytes.Buffer
	buf.WriteString("[Interface]\n")
	buf.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey))
	if !c.IsWireGuard {
		buf.WriteString(fmt.Sprintf("Jc = %d\n", c.Jc))
		buf.WriteString(fmt.Sprintf("Jmin = %d\n", c.Jmin))
		buf.WriteString(fmt.Sprintf("Jmax = %d\n", c.Jmax))
		buf.WriteString(fmt.Sprintf("S1 = %d\n", c.S1))
		buf.WriteString(fmt.Sprintf("S2 = %d\n", c.S2))
		buf.WriteString(fmt.Sprintf("H1 = %d\n", c.H1))
		buf.WriteString(fmt.Sprintf("H2 = %d\n", c.H2))
		buf.WriteString(fmt.Sprintf("H3 = %d\n", c.H3))
		buf.WriteString(fmt.Sprintf("H4 = %d\n", c.H4))
	}
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
		// Показываем только *.conf, не временные файлы
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") && !strings.HasPrefix(e.Name(), "._") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func activeConfigPath() string {
	return filepath.Join(awgDir, "active")
}

func getActiveConfigName() string {
	data, err := os.ReadFile(activeConfigPath())
	if err != nil {
		return "telegram.conf"
	}
	name := strings.TrimSpace(string(data))
	if _, err := os.Stat(filepath.Join(configsDir, name)); err != nil {
		return "telegram.conf"
	}
	return name
}

func saveActiveConfigName(name string) {
	os.WriteFile(activeConfigPath(), []byte(name), 0644)
}

func getCurrentConfig() *AWGConfig {
	name := getActiveConfigName()
	cfg, err := loadConfig(name)
	if err != nil {
		// fallback: telegram.conf
		cfg, err = loadConfig("telegram.conf")
	}
	if err == nil && cfg != nil && cfg.Address != "" {
		return cfg
	}
	// fallback: любой конфиг с Address
	for _, n := range listConfigs() {
		if cfg, err := loadConfig(n); err == nil && cfg.Address != "" {
			saveActiveConfigName(n)
			return cfg
		}
	}
	return nil
}

func saveConfig(name, data string) error {
	cfg, err := parseWGConfig(data)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(name, ".conf") {
		name += ".conf"
	}
	return cfg.Save(filepath.Join(configsDir, name))
}

func deleteConfig(name string) error {
	if !strings.HasSuffix(name, ".conf") {
		name += ".conf"
	}
	return os.Remove(filepath.Join(configsDir, name))
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

func findWireGuardGo() string {
	if p, err := exec.LookPath("wireguard-go"); err == nil {
		return p
	}
	if _, err := os.Stat("/opt/homebrew/bin/wireguard-go"); err == nil {
		return "/opt/homebrew/bin/wireguard-go"
	}
	return "wireguard-go"
}

func findActiveInterface() string {
	// Пробуем wg
	if out, err := sudo(wgBin, "show"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "interface: ") {
				iface := strings.TrimSpace(strings.TrimPrefix(line, "interface: "))
				// Не трогаем utun6 (штатный WG)
				if iface != "utun6" {
					return iface
				}
			}
		}
	}
	// Пробуем awg
	if out, err := sudo(awgBin, "show"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "interface: ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "interface: "))
			}
		}
	}
	return ""
}

func showInterface(iface string) (string, error) {
	if out, err := sudo(awgBin, "show", iface); err == nil && len(out) > 0 {
		return out, nil
	}
	return sudo(wgBin, "show", iface)
}

func isInterfaceAlive(iface string) bool {
	out, _ := showInterface(iface)
	return len(out) > 0
}

// === Sudo ===

func sudo(args ...string) (string, error) {
	args2 := append([]string{"-n"}, args...)
	cmd := exec.Command("sudo", args2...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir, "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
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
	iface := findActiveInterface()
	if iface == "" {
		return
	}
	for _, s := range loadRoutes() {
		for _, c := range strings.Fields(loadCIDRCache(s)) {
			sudo("route", "-q", "-n", "delete", strings.Split(c, "/")[0])
		}
	}
}

func wireguardUp(cfg *AWGConfig) string {
	ip := strings.Split(cfg.Address, "/")[0]

	// Ищем свободный utun (6 занят штатным WG)
	var freeDev string
	for i := 7; i <= 15; i++ {
		dev := fmt.Sprintf("utun%d", i)
		info, _ := exec.Command("ifconfig", dev).Output()
		s := string(info)
		if s == "" {
			freeDev = dev
			break
		}
	}
	if freeDev == "" {
		return "[ERROR] Нет свободных utun (7-15)"
	}
	iface := freeDev

	wgGo := findWireGuardGo()

	// Запускаем wireguard-go на интерфейсе
	startCmd := exec.Command("sudo", "-n", wgGo, iface)
	startCmd.Stdout = nil
	startCmd.Stderr = nil
	startCmd.Start()
	time.Sleep(3 * time.Second)

	if !isInterfaceAlive(iface) {
		return "[ERROR] wireguard-go не запустился на " + iface
	}

	// Назначаем IP
	sudo("/sbin/ifconfig", iface, ip, ip)

	// Применяем конфиг через wg setconf
	kernConf := filepath.Join(configsDir, "._wg_setconf")
	cfg.SaveKernelConfig(kernConf)
	sudo(wgBin, "setconf", iface, kernConf)
	os.Remove(kernConf)

	// Маршруты выбранных сервисов
	routes := loadAllCIDRs()
	if routes != "" {
		updateRoutes(iface, routes)
	}

	saveState(iface, ip)
	so, _ := showInterface(iface)
	out := fmt.Sprintf("[✓] "+tr("s.wg_up", iface)+"\n\n%s", so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] %s (%d %s)\n", tr("s.updated"), countCIDRs(routes), tr("s.nets"))
	}
	return out
}

func amneziawgUp(cfg *AWGConfig) string {
	ip := strings.Split(cfg.Address, "/")[0]

	// Свободный utun (не utun6)
	var freeDev string
	for i := 7; i <= 15; i++ {
		dev := fmt.Sprintf("utun%d", i)
		info, _ := exec.Command("ifconfig", dev).Output()
		s := string(info)
		if s == "" {
			freeDev = dev
			break
		}
	}
	if freeDev == "" {
		return "[ERROR] Нет свободных utun (7-15)"
	}
	iface := freeDev

	// Запускаем amneziawg-go
	startCmd := exec.Command("sudo", "-n", awgGo, iface)
	startCmd.Stdout = nil
	startCmd.Stderr = nil
	startCmd.Start()
	time.Sleep(3 * time.Second)

	if !isInterfaceAlive(iface) {
		return "[ERROR] amneziawg-go не запустился на " + iface
	}

	// Назначаем IP
	sudo("/sbin/ifconfig", iface, ip, ip)

	// Применяем конфиг
	kernConf := filepath.Join(configsDir, "._awg_setconf")
	cfg.SaveKernelConfig(kernConf)
	sudo(awgBin, "setconf", iface, kernConf)
	defer os.Remove(kernConf)

	// Маршруты выбранных сервисов
	routes := loadAllCIDRs()
	if routes != "" {
		updateRoutes(iface, routes)
	}

	saveState(iface, ip)
	so, _ := showInterface(iface)
	out := fmt.Sprintf("[✓] "+tr("s.awg_up", iface)+"\n\n%s", so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] %s (%d %s)\n", tr("s.updated"), countCIDRs(routes), tr("s.nets"))
	}
	return out
}

func cmdUp() string {
	cfg := getCurrentConfig()
	if cfg == nil || cfg.Address == "" {
		return "[ERROR] " + tr("s.config_needed")
	}

	// Если уже активен — просто шоу
	if iface := findActiveInterface(); iface != "" && isInterfaceAlive(iface) {
		out := fmt.Sprintf("[✓] %s %s\n", tr("s.already_up"), iface)
		so, _ := showInterface(iface)
		out += so
		return out
	}

	// Убиваем что могло остаться
	cmdDown()
	time.Sleep(1 * time.Second)

	if cfg.IsWireGuard {
		return wireguardUp(cfg)
	}
	return amneziawgUp(cfg)
}

type State struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}

func statePath() string       { return filepath.Join(stateDir, "current") }
func saveState(iface, ip string) {
	d, _ := json.Marshal(State{iface, ip})
	os.WriteFile(statePath(), d, 0644)
}
func clearState() { os.Remove(statePath()) }

func cmdDown() string {
	iface := findActiveInterface()
	if iface == "" {
		return "[!] " + tr("s.none_active")
	}
	removeAllRoutes()

	// Убиваем процесс (wireguard-go или amneziawg-go)
	for _, name := range []string{"wireguard-go", "amneziawg-go"} {
		pids, _ := exec.Command("pgrep", "-f", name+".*"+iface).Output()
		if len(pids) > 0 {
			sudo("kill", "-TERM", strings.TrimSpace(string(pids)))
			time.Sleep(1 * time.Second)
			sudo("kill", "-9", strings.TrimSpace(string(pids)))
		}
	}
	sudo("rm", "-f", fmt.Sprintf("/var/run/amneziawg/%s.sock", iface))
	sudo("rm", "-f", fmt.Sprintf("/var/run/wireguard/%s.sock", iface))
	clearState()
	return fmt.Sprintf("[✓] %s %s", iface, tr("s.down_iface"))
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
	iface := findActiveInterface()
	if iface == "" {
		return "[!] " + tr("s.none_active")
	}
	var out string
	out += fmt.Sprintf("=== %s ===\n", iface)
	if so, err := showInterface(iface); err == nil {
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
	out += "\n" + tr("s.output_routes") + "\n"
	routes := loadRoutes()
	if len(routes) == 0 {
		out += "  " + tr("s.no_services") + "\n"
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
	iface := findActiveInterface()
	if iface == "" {
		return "[!] " + tr("s.up_first")
	}
	routes := loadAllCIDRs()
	if routes == "" {
		return "[!] " + tr("s.no_services")
	}
	updateRoutes(iface, routes)
	return fmt.Sprintf("[✓] %s %s (%d %s)", tr("s.updated"), iface, countCIDRs(routes), tr("s.nets"))
}

func updateAllCIDRs() string {
	services, err := fetchServiceList()
	if err != nil {
		return "[WARN] " + tr("s.github_unavail")
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
				out += fmt.Sprintf("[✓] %s: %s (%d)\n", s.Name, tr("s.cached"), countCIDRs(cached))
			}
			continue
		}
		saveCIDRCache(s.Name, cidrData)
		out += fmt.Sprintf("[✓] %s: %s %d\n", s.Name, tr("s.loaded"), countCIDRs(cidrData))
	}
	return out
}

// === HTTP Server ===

var pageHTML string

func initPage() {
	pageHTML = `<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/png" href="data:image/png;base64,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">
<title>d-awg-router</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--green:#238636;--red:#da3633;--blue:#1f6feb;--purple:#8957e5;--gray:#6e7681}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg);padding:16px}
.container{max-width:960px;margin:0 auto}

/* header */
.header{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.header h1{font-size:1.3em;color:var(--accent)}
.header .sub{color:var(--muted);font-size:12px;flex:1}

/* status bar */
.status-bar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding:10px 14px;background:var(--card);border:1px solid var(--border);border-radius:8px;font-size:13px}
.status-item{display:flex;align-items:center;gap:6px}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.status-dot.green{background:var(--green)}
.status-dot.red{background:var(--red)}
.status-dot.yellow{background:#d29922}

/* tabs */
.tabs{display:flex;gap:0;margin-bottom:0;border-bottom:1px solid var(--border)}
.tab{padding:8px 18px;font-size:13px;cursor:pointer;border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;color:var(--muted);background:transparent;margin-bottom:-1px}
.tab:hover{color:var(--fg);background:rgba(255,255,255,0.05)}
.tab.active{color:var(--fg);background:var(--card);border-color:var(--border)}
.tab-content{display:none}
.tab-content.active{display:block}

/* cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:0 8px 8px 8px;padding:16px;margin-bottom:16px}
.card.flat{border-radius:8px}
.card h2{font-size:13px;color:var(--muted);text-transform:uppercase;margin-bottom:12px;letter-spacing:0.5px}
.card h3{font-size:14px;color:var(--fg);margin-bottom:10px}

/* buttons */
.btn{padding:8px 16px;border:none;border-radius:6px;font-size:13px;cursor:pointer;color:#fff;font-weight:500;display:inline-flex;align-items:center;gap:6px;transition:filter .15s}
.btn:hover{filter:brightness(1.2)}
.btn:disabled{opacity:0.35;cursor:not-allowed;filter:none}
.btn-up{background:var(--green)}
.btn-down{background:var(--red)}
.btn-restart{background:var(--blue)}
.btn-show{background:var(--gray)}
.btn-routes{background:var(--purple)}
.btn-save{background:var(--blue)}
.btn-sm{padding:5px 10px;font-size:12px}

.flex{display:flex;gap:8px;flex-wrap:wrap}
.mt{margin-top:12px}
.mb{margin-bottom:12px}

pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto}
pre.output-sm{max-height:200px}

textarea.config{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;color:var(--fg);font-family:monospace;font-size:12px;min-height:200px;resize:vertical}

.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px}
label.service{display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;font-size:13px;border-radius:6px;transition:background .15s}
label.service:hover{background:rgba(255,255,255,0.05)}
label.service input{margin:0;width:16px;height:16px;cursor:pointer}
.service-count{font-size:11px;color:var(--muted);margin-left:auto}

.error{color:#f85149}
.success{color:#3fb950}
.warning{color:#d29922}
.info{color:var(--muted)}

.config-nav-item{display:flex;align-items:center;gap:6px;padding:5px 8px;cursor:pointer;font-size:13px;border-radius:6px;transition:background .15s;margin-bottom:2px}
.config-nav-item:hover{background:rgba(255,255,255,0.05)}
.config-nav-item .cn-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.config-nav-item .cn-badge{font-size:11px;color:var(--accent);margin-left:4px}

/* responsive */
@media(max-width:640px){
  .tabs{overflow-x:auto}
  .tab{padding:8px 12px;white-space:nowrap}
  .grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
  <img src="/icon" alt="" width="28" height="28" style="border-radius:6px;flex-shrink:0">
  <h1>d-awg-router</h1>
  <span class="sub">WireGuard / AmneziaWG VPN Router</span>
  <div style="margin-left:auto;font-size:12px;display:flex;align-items:center;gap:4px">
    <span style="color:var(--muted)">__L_LANG__:</span>
    <select id="lang-select" onchange="switchLang(this.value)" style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:3px 6px;color:var(--fg);font-size:12px">
      <option value="en" __L_SEL_EN__>English</option>
      <option value="ru" __L_SEL_RU__>Русский</option>
    </select>
  </div>
</div>

<!-- Status Bar -->
<div class="status-bar">
  <span class="status-item">
    <span class="status-dot __STATUS_DOT__"></span>
    __STATUS_TEXT__
  </span>
  <span class="status-item" style="color:var(--muted)">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M1.5 8a6.5 6.5 0 1113 0 6.5 6.5 0 01-13 0zM8 0a8 8 0 100 16A8 8 0 008 0zM6.5 5.5a1.5 1.5 0 113 0 1.5 1.5 0 01-3 0zM7 9h2v4H7V9z"/></svg>
    __INTERFACE__
  </span>
  <span class="status-item" style="color:var(--muted)">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zM4.5 7.5a.5.5 0 010-1h1V5a.5.5 0 011 0v2.5a.5.5 0 01-.5.5h-1.5zm6 0a.5.5 0 010-1h1V5a.5.5 0 011 0v2.5a.5.5 0 01-.5.5h-1.5z"/></svg>
    __ROUTES__
  </span>
</div>

<!-- Tabs -->
<div class="tabs" id="tabs">
  <span class="tab active" data-tab="control">__L_TAB_CONTROL__</span>
  <span class="tab" data-tab="services">__L_TAB_SERVICES__</span>
  <span class="tab" data-tab="config">__L_TAB_CONFIG__</span>
</div>

<!-- Tab: Control -->
<div id="tab-control" class="tab-content active">
  <div class="card">
    <h2>__L_TAB_CONTROL__</h2>
    <form method="post" class="flex" onsubmit="return confirmAction(event)">
      <button class="btn btn-up" name="cmd" value="up" id="btn-up" __UP_DISABLED__>__L_BTN_UP__</button>
      <button class="btn btn-down" name="cmd" value="down" id="btn-down" __DOWN_DISABLED__>__L_BTN_DOWN__</button>
      <button class="btn btn-restart" name="cmd" value="restart" id="btn-restart" __RESTART_DISABLED__>__L_BTN_RESTART__</button>
      <button class="btn btn-show" name="cmd" value="show">SHOW</button>
      <button class="btn btn-routes" name="cmd" value="routes-force" id="btn-routes" __ROUTES_DISABLED__>ROUTES</button>
    </form>
  </div>
  <div class="card">
    <h2>__L_OUTPUT__</h2>
    <pre class="output-sm">__OUTPUT__</pre>
  </div>
</div>

<!-- Tab: Services -->
<div id="tab-services" class="tab-content">
  <div class="card flat">
    <form method="post">
      <div class="grid">__SERVICES__</div>
      <div class="flex mt">
        <button class="btn btn-save" name="cmd" value="save-services">__L_BTN_SAVE__</button>
        <button class="btn btn-routes" name="cmd" value="update-cidr">__L_BTN_LOAD__</button>
      </div>
    </form>
  </div>
</div>

<!-- Tab: Config -->
<div id="tab-config" class="tab-content">
  <div class="card flat" style="display:flex;gap:16px;flex-wrap:wrap">
    <div style="min-width:180px;flex-shrink:0">
      <h2>__L_CONFIG_TITLE__</h2>
      <div id="config-list" style="margin-bottom:10px">__CONFIG_LIST__</div>
      <button class="btn btn-sm btn-save" onclick="newConfig()">__L_BTN_NEW__</button>
    </div>
    <div style="flex:1;min-width:280px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
        <input type="text" id="config-name" value="__CONFIG_NAME__" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 10px;color:var(--fg);font-size:13px;flex:1;min-width:120px">
        <button class="btn btn-sm btn-save" onclick="saveConfig()">__L_BTN_SAVE__</button>
        <button class="btn btn-sm btn-restart" onclick="activateConfig()">__L_BTN_ACTIVATE__</button>
        <button class="btn btn-sm btn-down" onclick="deleteConfig()" id="btn-del-config">__L_BTN_DELETE__</button>
      </div>
      <textarea class="config" id="config-text" style="min-height:200px" placeholder="[Interface]&#10;Address = ...&#10;PrivateKey = ...">__CONFIG_TEXT__</textarea>
      <div id="config-msg" class="mt" style="font-size:13px">__CONFIG_MSG__</div>
    </div>
  </div>
</div>

</div>

<script>
// Tabs
document.addEventListener("click", function(e) {
  var tab = e.target.closest(".tab");
  if (!tab) return;
  var name = tab.dataset.tab;
  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active")});
  document.querySelectorAll(".tab-content").forEach(function(t){t.classList.remove("active")});
  tab.classList.add("active");
  document.getElementById("tab-"+name).classList.add("active");
});

function confirmAction(e) {
  var v = e.submitter.value;
  if (v==="down") return confirm("__L_CONFIRM_DOWN__");
  if (v==="restart") return confirm("__L_CONFIRM_RESTART__");
  return true;
}

// Config management
var currentConfig = '__CURRENT_CFG__';

function cfgName(name) {
  return name.endsWith('.conf') ? name : name + '.conf';
}
function cfgDisplay(name) {
  return name.replace(/\.conf$/,'');
}

function loadConfig(name) {
  currentConfig = cfgName(name);
  var x = new XMLHttpRequest();
  x.open('GET', '/api/config/load?name='+encodeURIComponent(currentConfig), true);
  x.onload = function() {
    var r = JSON.parse(x.responseText);
    if (r.error) { showCfgMsg('<span class="error">'+r.error+'</span>'); return; }
    document.getElementById('config-name').value = cfgDisplay(r.name);
    document.getElementById('config-text').value = r.text;
    document.getElementById('btn-del-config').style.display = '';
    renderConfigNav();
  };
  x.send();
}

function saveConfig() {
  var name = document.getElementById('config-name').value.trim();
  var text = document.getElementById('config-text').value;
  if (!name) { showCfgMsg('<span class="error">Enter config name</span>'); return; }
  if (!text) { showCfgMsg('<span class="error">Config is empty</span>'); return; }
  var oldName = currentConfig; // сохраняем старое имя для переименования
  var x = new XMLHttpRequest();
  x.open('POST', '/api/config/save', true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload = function() {
    var r = JSON.parse(x.responseText);
    if (r.error) { showCfgMsg('<span class="error">'+r.error+'</span>'); return; }
    currentConfig = cfgName(r.name);
    document.getElementById('config-name').value = cfgDisplay(currentConfig);
    showCfgMsg('<span class="success">'+r.message+'</span>');
    renderConfigNav();
  };
  x.send('name='+encodeURIComponent(name)+'&config='+encodeURIComponent(text)+'&old='+encodeURIComponent(oldName));
}

function deleteConfig() {
  if (!confirm('__L_CONFIRM_DEL__ "'+cfgDisplay(currentConfig)+'"?')) return;
  var x = new XMLHttpRequest();
  x.open('POST', '/api/config/delete', true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload = function() {
    var r = JSON.parse(x.responseText);
    if (r.error) { showCfgMsg('<span class="error">'+r.error+'</span>'); return; }
    showCfgMsg('<span class="success">'+r.message+'</span>');
    currentConfig = '';
    document.getElementById('config-name').value = '';
    document.getElementById('config-text').value = '';
    document.getElementById('btn-del-config').style.display = 'none';
    renderConfigNav();
  };
  x.send('name='+encodeURIComponent(currentConfig));
}

function activateConfig() {
  var name = document.getElementById('config-name').value.trim();
  if (!name) return;
  var x = new XMLHttpRequest();
  x.open('POST', '/api/config/activate', true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload = function() {
    var r = JSON.parse(x.responseText);
    if (r.error) { showCfgMsg('<span class="error">'+r.error+'</span>'); return; }
    showCfgMsg('<span class="success">'+r.message+'</span>');
    currentConfig = cfgName(r.name);
    renderConfigNav();
  };
  x.send('name='+encodeURIComponent(name));
}

function newConfig() {
  document.getElementById('config-name').value = '';
  document.getElementById('config-text').value = '';
  document.getElementById('btn-del-config').style.display = 'none';
  currentConfig = '';
  showCfgMsg('');
  renderConfigNav();
}

function renderConfigNav() {
  var x = new XMLHttpRequest();
  x.open('GET', '/api/configs', true);
  x.onload = function() {
    var r = JSON.parse(x.responseText);
    var html = '';
    for (var i = 0; i < r.configs.length; i++) {
      var c = r.configs[i];
      var badge = c.active ? ' <span class="cn-badge">●</span>' : '';
      var cls = 'config-nav-item';
      html += '<div class="'+cls+'" onclick="loadConfig(\''+c.name.replace(/'/g,"\\'")+'\')"><span class="cn-name">'+escHtml(c.display)+'</span>'+badge+'</div>';
    }
    document.getElementById('config-list').innerHTML = html;
  };
  x.send();
}

// Remove old functions
var currentConfig = '__CURRENT_CFG__';

function showCfgMsg(msg) {
  document.getElementById('config-msg').innerHTML = msg || '';
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function switchLang(l) {
  var x = new XMLHttpRequest();
  x.open('POST', '/api/lang', true);
  x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
  x.onload = function() { location.reload(); };
  x.send('lang='+encodeURIComponent(l));
}

// Initial load: load active config
window.onload = function() {
  renderConfigNav();
};
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

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string) {
	respondJSON(w, map[string]string{"error": msg})
}

func handler(w http.ResponseWriter, r *http.Request) {
	// API routes
	if strings.HasPrefix(r.URL.Path, "/api/") {
		handleAPI(w, r)
		return
	}
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
		if iface := findActiveInterface(); iface != "" {
			// Удаляем старые маршруты
			for _, s := range oldServices {
				for _, c := range strings.Fields(loadCIDRCache(s)) {
					sudo("route", "-q", "-n", "delete", strings.Split(c, "/")[0])
				}
			}
			// Добавляем новые
			if routes := loadAllCIDRs(); routes != "" {
				updateRoutes(iface, routes)
				out += fmt.Sprintf("\n[✓] %s (%d %s)", tr("s.updated"), countCIDRs(routes), tr("s.nets"))
			}
		}

		showPage(w, fmt.Sprintf(`<span class="success">%s</span><br>`, tr("s.saved"))+out)
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
	// Определяем статус
	iface := findActiveInterface()
	hasConfig := getCurrentConfig() != nil
	vpnActive := iface != ""

	statusDot := "red"
	statusText := "Offline"
	ifaceStr := "—"
	routesStr := "—"
	upDisabled := "disabled"
	downDisabled := "disabled"
	restartDisabled := "disabled"
	routesDisabled := "disabled"

	if hasConfig {
		upDisabled = ""
	}
	if vpnActive {
		statusDot = "green"
		statusText = "Connected"
		ifaceStr = iface
		downDisabled = ""
		restartDisabled = ""
		// считаем маршруты
		routeCount := 0
		routeOut, _ := exec.Command("netstat", "-rn", "-f", "inet").Output()
		for _, line := range strings.Split(string(routeOut), "\n") {
			if strings.Contains(line, iface) {
				routeCount++
			}
		}
		routesStr = fmt.Sprintf("%d routes", routeCount)
		if loadAllCIDRs() != "" {
			routesDisabled = ""
		}
	}
	if vpnActive && hasConfig {
		// всё уже установлено выше
	}

	repl := map[string]string{
		"__OUTPUT__":        output,
		"__CONFIG_MSG__":    "",
		"__CONFIG_TEXT__":   "",
		"__CONFIG_NAME__":   "",
		"__CONFIG_LIST__":   "",
		"__CURRENT_CFG__":   "",
		"__STATUS_DOT__":    statusDot,
		"__STATUS_TEXT__":   statusText,
		"__INTERFACE__":     ifaceStr,
		"__ROUTES__":        routesStr,
		"__UP_DISABLED__":   upDisabled,
		"__DOWN_DISABLED__": downDisabled,
		"__RESTART_DISABLED__": restartDisabled,
		"__ROUTES_DISABLED__":  routesDisabled,
		"__LANG__":          langName,
		"__L_TAB_CONTROL__": lang["tab.control"],
		"__L_TAB_SERVICES__": lang["tab.services"],
		"__L_TAB_CONFIG__":  lang["tab.config"],
		"__L_BTN_UP__":      lang["btn.up"],
		"__L_BTN_DOWN__":    lang["btn.down"],
		"__L_BTN_RESTART__": lang["btn.restart"],
		"__L_BTN_LOAD__":    lang["btn.load_routes"],
		"__L_BTN_SAVE__":    lang["btn.save"],
		"__L_BTN_ACTIVATE__": lang["btn.activate"],
		"__L_BTN_DELETE__":  lang["btn.delete"],
		"__L_BTN_NEW__":     lang["btn.new"],
		"__L_STATUS_ONLINE__": lang["status.online"],
		"__L_STATUS_OFFLINE__": lang["status.offline"],
		"__L_IFACE__":       lang["status.iface"],
		"__L_ROUTES__":      lang["status.routes"],
		"__L_SERVICES__":    lang["services.title"],
		"__L_CONFIG_TITLE__": lang["config.title"],
		"__L_OUTPUT__":      lang["output.label"],
		"__L_LANG__":        lang["lang.label"],
		"__L_ACTIVATED__":   lang["config.activated"],
		"__L_CFG_EMPTY__":   lang["config.empty_err"],
		"__L_CFG_NAME_ERR__": lang["config.name_err"],
		"__L_CFG_SAVED__":   lang["config.saved"],
		"__L_CFG_DELETED__": lang["config.deleted"],
		"__L_CONFIRM_DOWN__": lang["confirm.down"],
		"__L_CONFIRM_RESTART__": lang["confirm.restart"],
		"__L_CONFIRM_DEL__": lang["confirm.delete"],
		"__L_SEL_EN__": "",
		"__L_SEL_RU__": "",
	}
	if langName == "ru" {
		repl["__L_SEL_RU__"] = "selected"
	} else {
		repl["__L_SEL_EN__"] = "selected"
	}
	// Заполняем активный конфиг
	cfgName := getActiveConfigName()
	if cfg, err := loadConfig(cfgName); err == nil && cfg != nil && cfg.Address != "" {
		var buf bytes.Buffer
		buf.WriteString(fmt.Sprintf("[Interface]\nAddress = %s\nPrivateKey = %s\n", cfg.Address, cfg.PrivateKey))
		if cfg.DNS != "" {
			buf.WriteString(fmt.Sprintf("DNS = %s\n", cfg.DNS))
		}
		if !cfg.IsWireGuard {
			buf.WriteString(fmt.Sprintf("Jc = %d\nJmin = %d\nJmax = %d\n", cfg.Jc, cfg.Jmin, cfg.Jmax))
			buf.WriteString(fmt.Sprintf("S1 = %d\nS2 = %d\n", cfg.S1, cfg.S2))
			buf.WriteString(fmt.Sprintf("H1 = %d\nH2 = %d\nH3 = %d\nH4 = %d\n", cfg.H1, cfg.H2, cfg.H3, cfg.H4))
		}
		buf.WriteString(fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n", cfg.PublicKey, cfg.AllowedIPs, cfg.Endpoint, cfg.PKA))
		repl["__CONFIG_TEXT__"] = buf.String()
		repl["__CONFIG_NAME__"] = strings.TrimSuffix(cfgName, ".conf")
		repl["__CURRENT_CFG__"] = cfgName
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
		svcHTML.WriteString(`<span class="error">` + tr("s.github_unavail") + `</span>`)
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

func handleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api")
	path = strings.TrimSuffix(path, "/")

	switch path {
	case "/lang":
		if r.Method == "POST" {
			r.ParseForm()
			l := r.FormValue("lang")
			if _, ok := langData[l]; ok {
				langName = l
				lang = langData[l]
				os.WriteFile(filepath.Join(awgDir, "lang"), []byte(l), 0644)
				respondJSON(w, map[string]string{"lang": l})
				return
			}
		}
		respondJSON(w, map[string]string{"lang": langName})
	case "/configs":
		configs := listConfigs()
		active := getActiveConfigName()
		type ci struct {
			Name    string `json:"name"`
			Display string `json:"display"`
			Active  bool   `json:"active"`
		}
		items := make([]ci, 0, len(configs))
		for _, n := range configs {
			display := strings.TrimSuffix(n, ".conf")
			items = append(items, ci{
				Name: n, Display: display, Active: n == active,
			})
		}
		respondJSON(w, map[string]interface{}{
			"configs": items,
			"active":  active,
		})

	case "/config/load":
		name := r.URL.Query().Get("name")
		if name == "" {
			jsonError(w, "name required")
			return
		}
		data, err := os.ReadFile(filepath.Join(configsDir, name))
		if err != nil {
			jsonError(w, fmt.Sprintf("not found: %v", err))
			return
		}
		respondJSON(w, map[string]string{
			"name": name,
			"text": string(data),
		})

	case "/config/save":
		r.ParseForm()
		name := strings.TrimSpace(r.FormValue("name"))
		text := r.FormValue("config")
		old := r.FormValue("old")
		if name == "" || text == "" {
			jsonError(w, "name and config required")
			return
		}
		cfg, err := parseWGConfig(text)
		if err != nil {
			jsonError(w, err.Error())
			return
		}
		if !strings.HasSuffix(name, ".conf") {
			name += ".conf"
		}
		// If name changed, delete old config
		if old != "" && old != name {
			if !strings.HasSuffix(old, ".conf") {
				old += ".conf"
			}
			os.Remove(filepath.Join(configsDir, old))
			// If old was active, update active pointer
			if getActiveConfigName() == old {
				saveActiveConfigName(name)
			}
		}
		if err := cfg.Save(filepath.Join(configsDir, name)); err != nil {
			jsonError(w, fmt.Sprintf("save error: %v", err))
			return
		}
		respondJSON(w, map[string]string{
			"message": fmt.Sprintf("Saved %s", strings.TrimSuffix(name, ".conf")),
			"name":    name,
		})

	case "/config/delete":
		r.ParseForm()
		name := r.FormValue("name")
		if name == "" {
			jsonError(w, "name required")
			return
		}
		if !strings.HasSuffix(name, ".conf") {
			name += ".conf"
		}
		if err := os.Remove(filepath.Join(configsDir, name)); err != nil {
			jsonError(w, fmt.Sprintf("delete error: %v", err))
			return
		}
		// Если удаляем активный — сбрасываем на telegram.conf
		if getActiveConfigName() == name {
			saveActiveConfigName("telegram.conf")
		}
		respondJSON(w, map[string]string{
			"message": fmt.Sprintf("Deleted %s", strings.TrimSuffix(name, ".conf")),
		})

	case "/config/activate":
		r.ParseForm()
		name := r.FormValue("name")
		if name == "" {
			jsonError(w, "name required")
			return
		}
		if !strings.HasSuffix(name, ".conf") {
			name += ".conf"
		}
		if _, err := os.Stat(filepath.Join(configsDir, name)); err != nil {
			jsonError(w, fmt.Sprintf("not found: %s", name))
			return
		}
		saveActiveConfigName(name)
		respondJSON(w, map[string]string{
			"message": fmt.Sprintf("%s — %s", strings.TrimSuffix(name, ".conf"), lang["config.activated"]),
			"name":    name,
		})

	default:
		jsonError(w, "unknown API endpoint")
	}
}

func iconHandler(w http.ResponseWriter, r *http.Request) {
	iconPath := filepath.Join(awgDir, "awg-icon.png")
	// Fallback: relative to binary
	if _, err := os.Stat(iconPath); err != nil {
		iconPath = filepath.Join(homeDir, ".d-awg-router", "awg-icon.png")
	}
	data, err := os.ReadFile(iconPath)
	if err != nil {
		w.WriteHeader(404)
		w.Write([]byte("icon not found"))
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(data)
}

func main() {
	initPage()
	http.HandleFunc("/", handler)
	http.HandleFunc("/icon", iconHandler)
	addr := fmt.Sprintf("%s:%s", host, port)
	println("d-awg-router-web on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
