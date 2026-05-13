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
	appVersion string

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
	// Загрузка версии (из ~/.d-awg-router/version.txt с фолбэком на version.txt рядом с бинарником)
	verPath := filepath.Join(awgDir, "version.txt")
	if data, err := os.ReadFile(verPath); err == nil {
		appVersion = strings.TrimSpace(string(data))
	} else if exe, err := os.Executable(); err == nil {
		verPath := filepath.Join(filepath.Dir(exe), "version.txt")
		if data, err := os.ReadFile(verPath); err == nil {
			appVersion = strings.TrimSpace(string(data))
		}
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
	cfgName := getActiveConfigName()
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
	out := fmt.Sprintf("[✓] [%s] "+tr("s.wg_up", iface)+"\n\n%s", cfgName, so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] %s (%d %s)\n", tr("s.updated"), countCIDRs(routes), tr("s.nets"))
	}
	return out
}

func amneziawgUp(cfg *AWGConfig) string {
	cfgName := getActiveConfigName()
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
	out := fmt.Sprintf("[✓] [%s] "+tr("s.awg_up", iface)+"\n\n%s", cfgName, so)
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
	return fmt.Sprintf("[✓] [%s] %s %s", getActiveConfigName(), iface, tr("s.down_iface"))
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
  <h1>d-awg-router <span style="font-size:13px;color:var(--muted);font-weight:400">v__APP_VERSION__</span></h1>
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
		"__APP_VERSION__": appVersion,
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
