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
	wgBin       = "/opt/homebrew/bin/wg"
	awgBin      = "/usr/local/bin/awg"
	awgGo       = "/usr/local/bin/amneziawg-go"
)

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

func getCurrentConfig() *AWGConfig {
	// Сначала telegram.conf, потом любой другой
	cfg, err := loadConfig("telegram.conf")
	if err == nil && cfg.Address != "" {
		return cfg
	}
	// fallback: любой конфиг с Address
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
	out := fmt.Sprintf("[✓] WireGuard поднят на %s (через wireguard-go)\n\n%s", iface, so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] Маршруты добавлены (%d подсетей)\n", countCIDRs(routes))
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
	out := fmt.Sprintf("[✓] AmneziaWG поднят на %s\n\n%s", iface, so)
	if routes != "" {
		out += fmt.Sprintf("\n[✓] Маршруты добавлены (%d подсетей)\n", countCIDRs(routes))
	}
	return out
}

func cmdUp() string {
	cfg := getCurrentConfig()
	if cfg == nil || cfg.Address == "" {
		return "[ERROR] Нет загруженного конфига с Address. Загрузите WireGuard конфиг."
	}

	// Если уже активен — просто шоу
	if iface := findActiveInterface(); iface != "" && isInterfaceAlive(iface) {
		out := fmt.Sprintf("[✓] Уже активен на %s\n", iface)
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
		return "[!] Активный интерфейс не найден"
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
	iface := findActiveInterface()
	if iface == "" {
		return "[!] WG/AWG не активен"
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
	iface := findActiveInterface()
	if iface == "" {
		return "[!] WG/AWG не активен. Запустите UP сначала."
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
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3e%3crect x='0' y='0' width='512' height='512' rx='112' fill='%230d1117'/%3e%3cpath d='M256 60 L400 130 L400 280 Q400 400 256 460 Q112 400 112 280 L112 130 Z' fill='none' stroke='%2358a6ff' stroke-width='8' opacity='.6'/%3e%3cellipse cx='256' cy='240' rx='50' ry='40' fill='none' stroke='%2358a6ff' stroke-width='4' opacity='.3'/%3e%3cellipse cx='238' cy='230' rx='8' ry='10' fill='%230d1117' stroke='%2358a6ff' stroke-width='2'/%3e%3cellipse cx='274' cy='230' rx='8' ry='10' fill='%230d1117' stroke='%2358a6ff' stroke-width='2'/%3e%3c/svg%3e">
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
  <span class="tab active" data-tab="control">Control</span>
  <span class="tab" data-tab="services">Services</span>
  <span class="tab" data-tab="config">Config</span>
</div>

<!-- Tab: Control -->
<div id="tab-control" class="tab-content active">
  <div class="card">
    <h2>Управление VPN</h2>
    <form method="post" class="flex" onsubmit="return confirmAction(event)">
      <button class="btn btn-up" name="cmd" value="up" id="btn-up" __UP_DISABLED__>UP</button>
      <button class="btn btn-down" name="cmd" value="down" id="btn-down" __DOWN_DISABLED__>DOWN</button>
      <button class="btn btn-restart" name="cmd" value="restart" id="btn-restart" __RESTART_DISABLED__>RESTART</button>
      <button class="btn btn-show" name="cmd" value="show">SHOW</button>
      <button class="btn btn-routes" name="cmd" value="routes-force" id="btn-routes" __ROUTES_DISABLED__>ROUTES</button>
    </form>
  </div>
  <div class="card">
    <h2>Вывод</h2>
    <pre class="output-sm">__OUTPUT__</pre>
  </div>
</div>

<!-- Tab: Services -->
<div id="tab-services" class="tab-content">
  <div class="card flat">
    <form method="post">
      <div class="grid">__SERVICES__</div>
      <div class="flex mt">
        <button class="btn btn-save" name="cmd" value="save-services">Save Selection</button>
        <button class="btn btn-routes" name="cmd" value="update-cidr">Update CIDR</button>
      </div>
    </form>
  </div>
</div>

<!-- Tab: Config -->
<div id="tab-config" class="tab-content">
  <div class="card flat">
    <h2>WireGuard Config</h2>
    <form method="post">
      <textarea class="config" name="config" placeholder="[Interface]&#10;Address = ...&#10;PrivateKey = ...">__CONFIG_TEXT__</textarea>
      <div class="flex mt mb">
        <button class="btn btn-save" name="cmd" value="save-config">Save Config</button>
        <button class="btn btn-show" name="cmd" value="show-config">Show Current</button>
      </div>
    </form>
    __CONFIG_SAVED__
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
  if (v==="down") return confirm("Down VPN?");
  if (v==="restart") return confirm("Restart VPN?");
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
		"__CONFIG_SAVED__":  "",
		"__CONFIG_TEXT__":   "",
		"__STATUS_DOT__":    statusDot,
		"__STATUS_TEXT__":   statusText,
		"__INTERFACE__":     ifaceStr,
		"__ROUTES__":        routesStr,
		"__UP_DISABLED__":   upDisabled,
		"__DOWN_DISABLED__": downDisabled,
		"__RESTART_DISABLED__": restartDisabled,
		"__ROUTES_DISABLED__":  routesDisabled,
	}
	// Заполняем конфиг
	if cfg := getCurrentConfig(); cfg != nil {
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
