package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"gopkg.in/yaml.v3"
)

// NAT-PMP Constants (RFC 6886)
const (
	Version              = 0
	OpPublicIP           = 0
	OpMapUDP             = 1
	OpMapTCP             = 2
	ResultSuccess        = 0
	ResultNotAuth        = 2 // Returned for privileged port hijacking attempts
	ResultNetworkErr     = 3
	ResultOutOfResources = 4 // Returned for hitting max_ports_per_client limit
)

// Isolated runtime directory path matching systemd ProtectSystem constraints
const stateFilePath = "/run/firewalld-natpmp/state.json"

type Config struct {
	ListenInterface   string `yaml:"listen_interface"`
	ListenPort        int    `yaml:"listen_port"`
	FirewallZone      string `yaml:"firewall_zone"`
	MaxLifetime       uint32 `yaml:"max_lifetime"`
	MinPort           uint16 `yaml:"min_port"`
	MaxPortsPerClient int    `yaml:"max_ports_per_client"`
	AllowedSubnet     string `yaml:"allowed_subnet"`
	PublicIP          string `yaml:"public_ip"`
	WorkerPoolSize    int    `yaml:"worker_pool_size"`
}

type Lease struct {
	IntPort  uint16
	ExtPort  uint16
	Protocol string
	Timer    *time.Timer
}

type clientState struct {
	sync.Mutex
	activePorts map[string]*Lease // key: "proto:extPort"
}

type recoveryLease struct {
	IP      string `json:"ip"`
	Proto   string `json:"proto"`
	ExtPort uint16 `json:"ext_port"`
	IntPort uint16 `json:"int_port"`
}

var (
	startTime     = time.Now()
	config        Config
	sysBus        *dbus.Conn
	dbusMu        sync.RWMutex
	clientStates  sync.Map
	globalPorts   sync.Map // key: "proto:extPort" -> value: clientIP (string)
	allowedSubnet *net.IPNet
)

func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	if config.ListenPort == 0 {
		config.ListenPort = 5351
	}
	if config.MaxLifetime == 0 {
		config.MaxLifetime = 86400
	}
	if config.MinPort == 0 {
		config.MinPort = 1024
	}
	if config.MaxPortsPerClient == 0 {
		config.MaxPortsPerClient = 50
	}
	if config.WorkerPoolSize == 0 {
		config.WorkerPoolSize = 100
	}
	if config.AllowedSubnet != "" {
		_, ipNet, err := net.ParseCIDR(config.AllowedSubnet)
		if err != nil {
			return fmt.Errorf("invalid allowed_subnet: %v", err)
		}
		allowedSubnet = ipNet
	}

	return nil
}

func getDBusConn() (*dbus.Conn, error) {
	dbusMu.RLock()
	if sysBus != nil {
		obj := sysBus.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
		if call := obj.Call("org.freedesktop.DBus.Peer.Ping", 0); call.Err == nil {
			conn := sysBus
			dbusMu.RUnlock()
			return conn, nil
		}
	}
	dbusMu.RUnlock()

	dbusMu.Lock()
	defer dbusMu.Unlock()

	if sysBus != nil {
		obj := sysBus.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
		if call := obj.Call("org.freedesktop.DBus.Peer.Ping", 0); call.Err == nil {
			return sysBus, nil
		}
		sysBus.Close()
	}

	var err error
	sysBus, err = dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system D-Bus: %v", err)
	}
	return sysBus, nil
}

func getDefaultFirewallZone() string {
	conn, err := getDBusConn()
	if err != nil {
		log.Fatalf("Failed to establish D-Bus connection: %v", err)
	}
	obj := conn.Object("org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
	var zone string
	err = obj.Call("org.fedoraproject.FirewallD1.getDefaultZone", 0).Store(&zone)
	if err != nil {
		log.Fatalf("Failed to retrieve default firewalld zone via D-Bus: %v", err)
	}
	return zone
}

func syncStateToDisk() {
	var active []recoveryLease

	clientStates.Range(func(key, value any) bool {
		clientIP := key.(string)
		cs := value.(*clientState)
		cs.Lock()
		for _, lease := range cs.activePorts {
			active = append(active, recoveryLease{
				IP:      clientIP,
				Proto:   lease.Protocol,
				ExtPort: lease.ExtPort,
				IntPort: lease.IntPort,
			})
		}
		cs.Unlock()
		return true
	})

	data, err := json.Marshal(active)
	if err == nil {
		_ = os.WriteFile(stateFilePath, data, 0644)
	}
}

func recoverAndFlushState() {
	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return
	}

	var orphaned []recoveryLease
	if err := json.Unmarshal(data, &orphaned); err != nil {
		log.Printf("Failed to parse recovery state: %v", err)
		return
	}

	flushed := 0
	for _, lease := range orphaned {
		_ = manageFirewalldDBus(lease.Proto, lease.ExtPort, lease.IntPort, lease.IP, false)
		flushed++
	}

	if flushed > 0 {
		log.Printf("Startup flush removed %d orphaned NAT-PMP rules (Admin rules preserved)", flushed)
	}
	_ = os.Remove(stateFilePath)
}

func listenFirewalldReload() {
	conn, err := getDBusConn()
	if err != nil {
		log.Printf("Cannot listen for firewalld reloads: %v", err)
		return
	}

	err = conn.AddMatchSignal(
		dbus.WithMatchInterface("org.fedoraproject.FirewallD1"),
		dbus.WithMatchMember("Reloaded"),
	)
	if err != nil {
		log.Printf("Failed to subscribe to firewalld DBus signals: %v", err)
		return
	}

	c := make(chan *dbus.Signal, 10)
	conn.Signal(c)

	for v := range c {
		if v.Name == "org.fedoraproject.FirewallD1.Reloaded" {
			log.Println("Firewalld reload detected! Restoring active NAT-PMP leases...")
			restoreActiveRules()
		}
	}
}

func restoreActiveRules() {
	clientStates.Range(func(key, value any) bool {
		clientIP := key.(string)
		cs := value.(*clientState)
		cs.Lock()
		for _, lease := range cs.activePorts {
			err := manageFirewalldDBus(lease.Protocol, lease.ExtPort, lease.IntPort, clientIP, true)
			if err != nil {
				log.Printf("Failed to restore rule %s %d for %s: %v", lease.Protocol, lease.ExtPort, clientIP, err)
			}
		}
		cs.Unlock()
		return true
	})
}

func main() {
	configPath := flag.String("config", "/etc/firewalld-natpmp/config.yaml", "Path to configuration file")
	flag.Parse()

	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Println("Shutdown signal received. Tearing down active NAT-PMP rules...")
		
		clientStates.Range(func(key, value any) bool {
			clientIP := key.(string)
			cs := value.(*clientState)
			cs.Lock()
			for _, lease := range cs.activePorts {
				if lease.Timer != nil {
					lease.Timer.Stop()
				}
				_ = manageFirewalldDBus(lease.Protocol, lease.ExtPort, lease.IntPort, clientIP, false)
				log.Printf("Cleaned up orphaned rule: %s %d -> %s:%d", lease.Protocol, lease.ExtPort, clientIP, lease.IntPort)
			}
			cs.Unlock()
			return true
		})
		_ = os.Remove(stateFilePath)
		os.Exit(0)
	}()

	if config.FirewallZone == "" {
		config.FirewallZone = getDefaultFirewallZone()
		log.Printf("Auto-detected active firewalld zone: %s", config.FirewallZone)
	}

	recoverAndFlushState()
	go listenFirewalldReload()

	listenIP, err := getInterfaceIPv4(config.ListenInterface)
	if err != nil {
		log.Fatalf("Could not get IP for interface %s: %v", config.ListenInterface, err)
	}

	listenAddr := fmt.Sprintf("%s:%d", listenIP, config.ListenPort)
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to resolve address %s: %v", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to bind to UDP %s: %v", listenAddr, err)
	}
	defer conn.Close()

	log.Printf("NAT-PMP daemon listening on %s (Zone: %s)", listenAddr, config.FirewallZone)

	sem := make(chan struct{}, config.WorkerPoolSize)
	buf := make([]byte, 256)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		sem <- struct{}{}
		go func(addr *net.UDPAddr, data []byte) {
			defer func() { <-sem }()
			handlePacket(conn, addr, data)
		}(clientAddr, packetData)
	}
}

func getInterfaceIPv4(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address found on %s", ifaceName)
}

func getOutboundIP() net.IP {
	if config.PublicIP != "" {
		if ip := net.ParseIP(config.PublicIP); ip != nil {
			return ip.To4()
		}
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Printf("Warning: Could not determine external IP: %v", err)
		return net.ParseIP("0.0.0.0").To4()
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.To4()
}

func handlePacket(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
	if allowedSubnet != nil && !allowedSubnet.Contains(client.IP) {
		log.Printf("Security drop: Packet from unauthorized IP subnet alignment: %s", client.IP.String())
		return
	}

	if len(data) < 2 || data[0] != Version {
		return
	}

	opCode := data[1]
	switch opCode {
	case OpPublicIP:
		handlePublicIPRequest(conn, client)
	case OpMapUDP, OpMapTCP:
		if len(data) < 12 {
			return
		}
		handleMappingRequest(conn, client, data)
	}
}

func handlePublicIPRequest(conn *net.UDPConn, client *net.UDPAddr) {
	ip := getOutboundIP()
	uptime := uint32(time.Since(startTime).Seconds())

	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint8(Version))
	_ = binary.Write(buf, binary.BigEndian, uint8(OpPublicIP+128))
	_ = binary.Write(buf, binary.BigEndian, uint16(ResultSuccess))
	_ = binary.Write(buf, binary.BigEndian, uptime)
	_, _ = buf.Write(ip)

	_, _ = conn.WriteToUDP(buf.Bytes(), client)
}

func handleMappingRequest(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
	opCode := data[1]
	intPort := binary.BigEndian.Uint16(data[4:6])
	extPort := binary.BigEndian.Uint16(data[6:8])
	lifetime := binary.BigEndian.Uint32(data[8:12])

	proto := "udp"
	if opCode == OpMapTCP {
		proto = "tcp"
	}

	clientIP := client.IP.String()

	if intPort == 0 {
		handleTeardown(conn, client, opCode, extPort, proto)
		return
	}

	var allocated bool
	if extPort == 0 {
		var ok bool
		extPort, ok = allocateEphemeralPort(clientIP, proto)
		if !ok {
			log.Printf("Resource exhaustion: Ephemeral allocations spent for client %s", clientIP)
			sendError(conn, client, opCode, ResultOutOfResources)
			return
		}
		allocated = true
	}

	key := fmt.Sprintf("%s:%d", proto, extPort)

	if !allocated {
		if extPort < config.MinPort {
			log.Printf("Security alert: Client %s attempted privileged port hijacking: %d", clientIP, extPort)
			sendError(conn, client, opCode, ResultNotAuth)
			return
		}

		actualClient, loaded := globalPorts.LoadOrStore(key, clientIP)
		if loaded && actualClient.(string) != clientIP {
			log.Printf("Conflict: External port lease mapping %s already held by %s", key, actualClient.(string))
			sendError(conn, client, opCode, ResultOutOfResources)
			return
		}
	}

	if lifetime > config.MaxLifetime {
		lifetime = config.MaxLifetime
	}

	if !checkLeaseLimit(clientIP, key, lifetime) {
		log.Printf("Security alert: Client %s exceeded active port map exhaustion constraints", clientIP)
		if allocated {
			globalPorts.Delete(key)
		}
		sendError(conn, client, opCode, ResultOutOfResources)
		return
	}

	val, _ := clientStates.Load(clientIP)
	isRenewal := false
	if val != nil {
		cs := val.(*clientState)
		cs.Lock()
		if oldLease, exists := cs.activePorts[key]; exists && oldLease.IntPort == intPort {
			isRenewal = true
		}
		cs.Unlock()
	}

	if !isRenewal {
		err := manageFirewalldDBus(proto, extPort, intPort, clientIP, true)
		if err != nil {
			log.Printf("D-Bus rule transaction dropped: %v", err)
			if allocated || lifetime == 0 {
				globalPorts.Delete(key)
			}
			sendError(conn, client, opCode, ResultNetworkErr)
			return
		}
	}

	commitLease(clientIP, proto, extPort, intPort, lifetime)
	sendMappingResponse(conn, client, opCode, intPort, extPort, lifetime)

	if lifetime > 0 {
		if isRenewal {
			log.Printf("Renewed %s %d -> %s:%d for %ds", proto, extPort, clientIP, intPort, lifetime)
		} else {
			log.Printf("Mapped %s %d -> %s:%d for %ds", proto, extPort, clientIP, intPort, lifetime)
		}
	} else {
		log.Printf("Removed mapping %s %d -> %s:%d", proto, extPort, clientIP, intPort)
	}
}

func handleTeardown(conn *net.UDPConn, client *net.UDPAddr, opCode uint8, extPort uint16, proto string) {
	clientIP := client.IP.String()
	val, ok := clientStates.Load(clientIP)
	if !ok {
		sendMappingResponse(conn, client, opCode, 0, 0, 0)
		return
	}

	cs := val.(*clientState)
	cs.Lock()
	defer cs.Unlock()

	removeAll := (extPort == 0)

	for key, lease := range cs.activePorts {
		if removeAll || (lease.Protocol == proto && lease.ExtPort == extPort) {
			if lease.Timer != nil {
				lease.Timer.Stop()
			}
			_ = manageFirewalldDBus(lease.Protocol, lease.ExtPort, lease.IntPort, clientIP, false)
			globalPorts.Delete(key)
			delete(cs.activePorts, key)
		}
	}

	sendMappingResponse(conn, client, opCode, 0, extPort, 0)
	go syncStateToDisk()
}

func sendMappingResponse(conn *net.UDPConn, client *net.UDPAddr, opCode uint8, intPort, extPort uint16, lifetime uint32) {
	uptime := uint32(time.Since(startTime).Seconds())
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint8(Version))
	_ = binary.Write(buf, binary.BigEndian, uint8(opCode+128))
	_ = binary.Write(buf, binary.BigEndian, uint16(ResultSuccess))
	_ = binary.Write(buf, binary.BigEndian, uptime)
	_ = binary.Write(buf, binary.BigEndian, intPort)
	_ = binary.Write(buf, binary.BigEndian, extPort)
	_ = binary.Write(buf, binary.BigEndian, lifetime)
	_, _ = conn.WriteToUDP(buf.Bytes(), client)
}

func sendError(conn *net.UDPConn, client *net.UDPAddr, reqOp uint8, errCode uint16) {
	uptime := uint32(time.Since(startTime).Seconds())
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint8(Version))
	_ = binary.Write(buf, binary.BigEndian, uint8(reqOp+128))
	_ = binary.Write(buf, binary.BigEndian, errCode)
	_ = binary.Write(buf, binary.BigEndian, uptime)

	if reqOp == OpMapUDP || reqOp == OpMapTCP {
		_ = binary.Write(buf, binary.BigEndian, uint16(0)) 
		_ = binary.Write(buf, binary.BigEndian, uint16(0)) 
		_ = binary.Write(buf, binary.BigEndian, uint32(0)) 
	}

	_, _ = conn.WriteToUDP(buf.Bytes(), client)
}

func manageFirewalldDBus(proto string, extPort, intPort uint16, ip string, isAdd bool) error {
	conn, err := getDBusConn()
	if err != nil {
		return fmt.Errorf("D-Bus operational failure: %v", err)
	}

	obj := conn.Object("org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
	extStr := strconv.Itoa(int(extPort))
	intStr := strconv.Itoa(int(intPort))

	if isAdd {
		call := obj.Call("org.fedoraproject.FirewallD1.zone.addForwardPort", 0,
			config.FirewallZone, extStr, proto, intStr, ip, int32(0))

		if call.Err != nil {
			if strings.Contains(call.Err.Error(), "ALREADY_ENABLED") {
				_ = obj.Call("org.fedoraproject.FirewallD1.zone.removeForwardPort", 0,
					config.FirewallZone, extStr, proto, intStr, ip)
				call = obj.Call("org.fedoraproject.FirewallD1.zone.addForwardPort", 0,
					config.FirewallZone, extStr, proto, intStr, ip, int32(0))
			}
			return call.Err
		}
		return nil
	}

	call := obj.Call("org.fedoraproject.FirewallD1.zone.removeForwardPort", 0,
		config.FirewallZone, extStr, proto, intStr, ip)

	if call.Err != nil && call.Err.Error() != "INVALID_RULE" && call.Err.Error() != "NOT_ENABLED" {
		return call.Err
	}
	return nil
}

func allocateEphemeralPort(clientIP string, proto string) (uint16, bool) {
	maxPort := uint16(65535)
	if config.MinPort >= maxPort {
		return 0, false
	}
	rangeSize := int(maxPort - config.MinPort + 1)

	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return 0, false
	}
	start := int(nBig.Int64())

	for i := 0; i < rangeSize; i++ {
		p := config.MinPort + uint16((start+i)%rangeSize)
		key := fmt.Sprintf("%s:%d", proto, p)
		if _, loaded := globalPorts.LoadOrStore(key, clientIP); !loaded {
			return p, true
		}
	}
	return 0, false
}

func checkLeaseLimit(ip string, key string, lifetime uint32) bool {
	if lifetime == 0 {
		return true
	}
	val, _ := clientStates.LoadOrStore(ip, &clientState{activePorts: make(map[string]*Lease)})
	cs := val.(*clientState)
	cs.Lock()
	defer cs.Unlock()

	_, exists := cs.activePorts[key]
	if !exists && len(cs.activePorts) >= config.MaxPortsPerClient {
		return false
	}
	return true
}

func commitLease(ip string, proto string, extPort, intPort uint16, lifetime uint32) {
	key := fmt.Sprintf("%s:%d", proto, extPort)
	val, _ := clientStates.LoadOrStore(ip, &clientState{activePorts: make(map[string]*Lease)})
	cs := val.(*clientState)
	cs.Lock()
	defer cs.Unlock()

	if oldLease, exists := cs.activePorts[key]; exists {
		if oldLease.Timer != nil {
			oldLease.Timer.Stop()
		}
	}

	if lifetime > 0 {
		globalPorts.Store(key, ip)
		lease := &Lease{
			IntPort:  intPort,
			ExtPort:  extPort,
			Protocol: proto,
		}
		lease.Timer = time.AfterFunc(time.Duration(lifetime)*time.Second, func() {
			cs.Lock()
			delete(cs.activePorts, key)
			cs.Unlock()
			globalPorts.Delete(key)

			_ = manageFirewalldDBus(proto, extPort, intPort, ip, false)
			log.Printf("Lease expired: Removed mapping %s %d -> %s:%d", proto, extPort, ip, intPort)
			go syncStateToDisk()
		})
		cs.activePorts[key] = lease
	} else {
		delete(cs.activePorts, key)
		globalPorts.Delete(key)
	}

	go syncStateToDisk()
}
