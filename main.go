package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
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

type Config struct {
	ListenInterface   string `yaml:"listen_interface"`
	ListenPort        int    `yaml:"listen_port"`
	FirewallZone      string `yaml:"firewall_zone"`
	MaxLifetime       uint32 `yaml:"max_lifetime"`
	MinPort           uint16 `yaml:"min_port"`
	MaxPortsPerClient int    `yaml:"max_ports_per_client"`
}

type clientState struct {
	sync.Mutex
	activePorts map[uint16]*time.Timer
}

var (
	startTime    = time.Now()
	config       Config
	sysBus       *dbus.Conn
	clientStates sync.Map
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

	// Apply robust defaults
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

	return nil
}

func initDBus() error {
	var err error
	if sysBus != nil {
		sysBus.Close()
	}
	sysBus, err = dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system D-Bus: %v", err)
	}
	return nil
}

// ensureDBusConnection checks if the socket connection is alive.
// If firewalld restarted, it seamlessly rebuilds the connection.
func ensureDBusConnection() error {
	if sysBus == nil {
		return initDBus()
	}

	// Light peer ping to verify connection integrity
	obj := sysBus.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	call := obj.Call("org.freedesktop.DBus.Peer.Ping", 0)
	if call.Err != nil {
		log.Println("D-Bus connection severed. Attempting reconnection...")
		return initDBus()
	}
	return nil
}

func getDefaultFirewallZone() string {
	obj := sysBus.Object("org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
	var zone string
	err := obj.Call("org.fedoraproject.FirewallD1.getDefaultZone", 0).Store(&zone)
	if err != nil {
		log.Fatalf("Failed to retrieve default firewalld zone via D-Bus: %v", err)
	}
	return zone
}

func main() {
	configPath := flag.String("config", "/etc/firewalld-natpmp/config.yaml", "Path to configuration file")
	flag.Parse()

	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	if err := initDBus(); err != nil {
		log.Fatalf("Initial D-Bus connection failed: %v", err)
	}
	defer func() {
		if sysBus != nil {
			sysBus.Close()
		}
	}()

	if config.FirewallZone == "" {
		config.FirewallZone = getDefaultFirewallZone()
		log.Printf("Auto-detected active firewalld zone: %s", config.FirewallZone)
	}

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

	buf := make([]byte, 256)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		// Security: Create a unique slice copy per packet to prevent goroutine buffer corruption
		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		go handlePacket(conn, clientAddr, packetData)
	}
}

// --- Dynamic Network Helpers ---

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
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Printf("Warning: Could not determine external IP: %v", err)
		return net.ParseIP("0.0.0.0").To4()
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.To4()
}

// --- NAT-PMP Protocol Handlers ---

func handlePacket(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
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
	binary.Write(buf, binary.BigEndian, uint8(Version))
	binary.Write(buf, binary.BigEndian, uint8(OpPublicIP+128))
	binary.Write(buf, binary.BigEndian, uint16(ResultSuccess))
	binary.Write(buf, binary.BigEndian, uptime)
	buf.Write(ip)

	conn.WriteToUDP(buf.Bytes(), client)
	log.Printf("Sent Public IP (%s) to %s", ip.String(), client.IP.String())
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

	if extPort == 0 {
		extPort = intPort
	}

	clientIP := client.IP.String()

	// Security: Block privileged host service hijacking attempts
	if extPort < config.MinPort {
		log.Printf("Security alert: Client %s attempted to hijack privileged port %d", clientIP, extPort)
		sendError(conn, client, opCode, ResultNotAuth)
		return
	}

	if lifetime > config.MaxLifetime {
		log.Printf("Requested lifetime %ds exceeds maximum. Capping to %ds.", lifetime, config.MaxLifetime)
		lifetime = config.MaxLifetime
	}

	// Security: Track and limit total active leases allocated per individual IP
	if !trackAndLimitLease(clientIP, extPort, lifetime) {
		log.Printf("Security alert: Client %s denied mapping; hit maximum allowed port limit (%d)", clientIP, config.MaxPortsPerClient)
		sendError(conn, client, opCode, ResultOutOfResources)
		return
	}

	err := manageFirewalldDBus(proto, extPort, intPort, clientIP, lifetime)
	if err != nil {
		log.Printf("D-Bus transaction failed: %v", err)
		trackAndLimitLease(clientIP, extPort, 0) // Undo RAM state allocation tracking on total failure
		sendError(conn, client, opCode, ResultNetworkErr)
		return
	}

	uptime := uint32(time.Since(startTime).Seconds())
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(Version))
	binary.Write(buf, binary.BigEndian, uint8(opCode+128))
	binary.Write(buf, binary.BigEndian, uint16(ResultSuccess))
	binary.Write(buf, binary.BigEndian, uptime)
	binary.Write(buf, binary.BigEndian, intPort)
	binary.Write(buf, binary.BigEndian, extPort)
	binary.Write(buf, binary.BigEndian, lifetime)

	conn.WriteToUDP(buf.Bytes(), client)

	if lifetime > 0 {
		log.Printf("Mapped %s %d -> %s:%d for %ds", proto, extPort, clientIP, intPort, lifetime)
	} else {
		log.Printf("Removed mapping %s %d -> %s:%d", proto, extPort, clientIP, intPort)
	}
}

func sendError(conn *net.UDPConn, client *net.UDPAddr, reqOp uint8, errCode uint16) {
	uptime := uint32(time.Since(startTime).Seconds())
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(Version))
	binary.Write(buf, binary.BigEndian, uint8(reqOp+128))
	binary.Write(buf, binary.BigEndian, errCode)
	binary.Write(buf, binary.BigEndian, uptime)
	conn.WriteToUDP(buf.Bytes(), client)
}

func manageFirewalldDBus(proto string, extPort, intPort uint16, ip string, lifetime uint32) error {
	if err := ensureDBusConnection(); err != nil {
		return fmt.Errorf("D-Bus operational failure: %v", err)
	}

	obj := sysBus.Object("org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")

	extStr := strconv.Itoa(int(extPort))
	intStr := strconv.Itoa(int(intPort))

	if lifetime > 0 {
		// Native firewalld signature handles timeouts directly inside the system message bus daemon
		call := obj.Call("org.fedoraproject.FirewallD1.zone.addForwardPort", 0,
			config.FirewallZone, extStr, proto, intStr, ip, int32(lifetime))
		return call.Err
	}

	call := obj.Call("org.fedoraproject.FirewallD1.zone.removeForwardPort", 0,
		config.FirewallZone, extStr, proto, intStr, ip)

	// Suppress warnings when wiping mappings that do not exist or were dropped via external changes
	if call.Err != nil && call.Err.Error() != "INVALID_RULE" && call.Err.Error() != "NOT_ENABLED" {
		return call.Err
	}
	return nil
}

func trackAndLimitLease(ip string, port uint16, lifetime uint32) bool {
	val, _ := clientStates.LoadOrStore(ip, &clientState{activePorts: make(map[uint16]*time.Timer)})
	cs := val.(*clientState)

	cs.Lock()
	defer cs.Unlock()

	if timer, exists := cs.activePorts[port]; exists {
		timer.Stop()
	} else if len(cs.activePorts) >= config.MaxPortsPerClient && lifetime > 0 {
		return false
	}

	if lifetime > 0 {
		// Maintain parity with firewalld's automatic kernel timeout routine
		cs.activePorts[port] = time.AfterFunc(time.Duration(lifetime)*time.Second, func() {
			cs.Lock()
			delete(cs.activePorts, port)
			cs.Unlock()
		})
	} else {
		delete(cs.activePorts, port)
	}

	return true
}
