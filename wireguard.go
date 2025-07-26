package main

/*
#include <stdlib.h>

typedef struct {
	char** Names;
	int    Count;
} InterfacesNameResponse;

typedef struct {
	char* InterfacePrivKey;
	char* InterfacePubKey;
	int   InterfaceListenPort;
	char* InterfaceAddress;
	char* InterfaceDNS;
	char* PeerPubKey;
	char* PeerEndpointAddress;
	char* PeerAllowedIPs;
	char* PeerPersistentKeepalive;
	char* PeerPresharedKey;
} ConfigResponse;

typedef struct {
	char* LastHandshakeTime;
	char* Transfer;
} StatsResponse;
*/
import "C"

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//export readInterfacesName
func readInterfacesName() *C.InterfacesNameResponse {
	configDirs := []string{
		"/etc/wireguard/",
		"/usr/local/etc/wireguard/",
	}

	devices := make([]string, 0)

	for _, dir := range configDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".conf") {
				name := strings.TrimSuffix(file.Name(), ".conf")
				devices = append(devices, name)
			}
		}
	}

	if len(devices) == 0 {
		return nil
	}

	cNames := C.malloc(C.size_t(len(devices)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	names := (*[1 << 30]*C.char)(unsafe.Pointer(cNames))[:len(devices):len(devices)]

	for i, device := range devices {
		names[i] = C.CString(device)
	}

	interfaces := (*C.InterfacesNameResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.InterfacesNameResponse{}))))
	interfaces.Names = (**C.char)(cNames)
	interfaces.Count = C.int(len(devices))
	return interfaces
}

//export readConfig
func readConfig(name *C.char) *C.ConfigResponse {
	client, err := wgctrl.New()
	if err != nil {
		return nil
	}
	defer client.Close()

	cfg := (*C.ConfigResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.ConfigResponse{}))))
	cfg.InterfacePrivKey = C.CString("")
	cfg.InterfacePubKey = C.CString("")
	cfg.InterfaceListenPort = 0
	cfg.InterfaceAddress = C.CString("")
	cfg.InterfaceDNS = C.CString("")
	cfg.PeerPubKey = C.CString("")
	cfg.PeerEndpointAddress = C.CString("")
	cfg.PeerAllowedIPs = C.CString("")
	cfg.PeerPersistentKeepalive = C.CString("")
	cfg.PeerPresharedKey = C.CString("")

	device, err := client.Device(C.GoString(name))
	if err != nil {
		interfacePubKey, peerPubKey := parseKeys(C.GoString(name))
		if interfacePubKey == "" && peerPubKey == "" {
			return nil
		}

		cfg.InterfacePubKey = C.CString(interfacePubKey)
		cfg.PeerPubKey = C.CString(peerPubKey)
		return cfg
	}

	if len(device.Peers) == 0 {
		return nil
	}

	address, dns, alive, psk := parseConfig(C.GoString(name))

	peer := device.Peers[0]

	ips := make([]string, 0)
	for _, ipNet := range peer.AllowedIPs {
		ips = append(ips, ipNet.String())
	}

	cfg.InterfacePrivKey = C.CString(device.PrivateKey.String())
	cfg.InterfacePubKey = C.CString(device.PublicKey.String())
	cfg.InterfaceListenPort = C.int(device.ListenPort)
	cfg.InterfaceAddress = C.CString(address)
	cfg.InterfaceDNS = C.CString(dns)
	cfg.PeerPubKey = C.CString(peer.PublicKey.String())
	cfg.PeerEndpointAddress = C.CString(peer.Endpoint.String())
	cfg.PeerAllowedIPs = C.CString(strings.Join(ips, ","))
	cfg.PeerPersistentKeepalive = C.CString(alive)
	cfg.PeerPresharedKey = C.CString(psk)
	return cfg
}

//export readStats
func readStats(name *C.char) *C.StatsResponse {
	client, err := wgctrl.New()
	if err != nil {
		return nil
	}
	defer client.Close()

	cfg := (*C.StatsResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.StatsResponse{}))))
	cfg.LastHandshakeTime = C.CString("")
	cfg.Transfer = C.CString("")

	device, err := client.Device(C.GoString(name))
	if err != nil {
		return nil
	}

	if len(device.Peers) == 0 {
		return nil
	}

	peer := device.Peers[0]

	cfg.LastHandshakeTime = C.CString(parseTime(peer.LastHandshakeTime))
	cfg.Transfer = C.CString(parseTraffic(peer.ReceiveBytes, peer.TransmitBytes))
	return cfg
}

//export generateKeys
func generateKeys(privKey **C.char, pubKey **C.char) *C.char {
	generate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return C.CString(err.Error())
	}

	*privKey = C.CString(generate.String())
	*pubKey = C.CString(generate.PublicKey().String())

	return nil
}

//export freeInterfacesName
func freeInterfacesName(interfaces *C.InterfacesNameResponse) {
	if interfaces != nil {
		if interfaces.Count > 0 {
			names := (*[1 << 30]*C.char)(unsafe.Pointer(interfaces.Names))[:interfaces.Count:interfaces.Count]

			for i := range int(interfaces.Count) {
				C.free(unsafe.Pointer(names[i]))
			}
			C.free(unsafe.Pointer(interfaces.Names))
		}
		C.free(unsafe.Pointer(interfaces))
	}
}

//export freeConfig
func freeConfig(cfg *C.ConfigResponse) {
	if cfg != nil {
		if cfg.InterfacePrivKey != nil {
			C.free(unsafe.Pointer(cfg.InterfacePrivKey))
		}
		if cfg.InterfacePubKey != nil {
			C.free(unsafe.Pointer(cfg.InterfacePubKey))
		}
		if cfg.InterfaceAddress != nil {
			C.free(unsafe.Pointer(cfg.InterfaceAddress))
		}
		if cfg.InterfaceDNS != nil {
			C.free(unsafe.Pointer(cfg.InterfaceDNS))
		}
		if cfg.PeerEndpointAddress != nil {
			C.free(unsafe.Pointer(cfg.PeerEndpointAddress))
		}
		if cfg.PeerPubKey != nil {
			C.free(unsafe.Pointer(cfg.PeerPubKey))
		}
		if cfg.PeerAllowedIPs != nil {
			C.free(unsafe.Pointer(cfg.PeerAllowedIPs))
		}
		if cfg.PeerPersistentKeepalive != nil {
			C.free(unsafe.Pointer(cfg.PeerPersistentKeepalive))
		}
		if cfg.PeerPresharedKey != nil {
			C.free(unsafe.Pointer(cfg.PeerPresharedKey))
		}
		C.free(unsafe.Pointer(cfg))
	}
}

//export freeStats
func freeStats(cfg *C.StatsResponse) {
	if cfg != nil {
		if cfg.LastHandshakeTime != nil {
			C.free(unsafe.Pointer(cfg.LastHandshakeTime))
		}
		if cfg.Transfer != nil {
			C.free(unsafe.Pointer(cfg.Transfer))
		}
		C.free(unsafe.Pointer(cfg))
	}
}

//export freeString
func freeString(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

func parseConfig(interfaceName string) (string, string, string, string) {
	var address, dns, alive, psk string

	paths := []string{
		filepath.Join("/etc/wireguard/" + interfaceName + ".conf"),
		filepath.Join("/usr/local/etc/wireguard/" + interfaceName + ".conf"),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for line := range bytes.SplitSeq(data, []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("Address = ")) {
				address = string(bytes.TrimPrefix(line, []byte("Address = ")))
			}
			if bytes.HasPrefix(line, []byte("DNS = ")) {
				dns = string(bytes.TrimPrefix(line, []byte("DNS = ")))
			}
			if bytes.HasPrefix(line, []byte("PersistentKeepalive = ")) {
				alive = string(bytes.TrimPrefix(line, []byte("PersistentKeepalive = ")))
			}
			if bytes.HasPrefix(line, []byte("PresharedKey = ")) {
				psk = string(bytes.TrimPrefix(line, []byte("PresharedKey = ")))
			}
		}
	}

	return address, dns, alive, psk
}

func parseKeys(interfaceName string) (string, string) {
	var privKey, pubKey string

	paths := []string{
		filepath.Join("/etc/wireguard/" + interfaceName + ".conf"),
		filepath.Join("/usr/local/etc/wireguard/" + interfaceName + ".conf"),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for line := range bytes.SplitSeq(data, []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("PrivateKey = ")) {
				privKey = string(bytes.TrimPrefix(line, []byte("PrivateKey = ")))
			}
			if bytes.HasPrefix(line, []byte("PublicKey = ")) {
				pubKey = string(bytes.TrimPrefix(line, []byte("PublicKey = ")))
			}
		}
	}

	if privKey != "" && pubKey != "" {
		convert, err := wgtypes.ParseKey(privKey)
		if err != nil {
			return "", ""
		}

		return convert.PublicKey().String(), pubKey
	}

	return "", ""
}

func parseTime(handshake time.Time) string {
	if handshake.IsZero() {
		return "never"
	}

	diff := time.Since(handshake)
	if diff < time.Second {
		return "now"
	}

	days := int(diff.Hours() / 24)
	hours := int(diff.Hours()) % 24
	minutes := int(diff.Minutes()) % 60
	seconds := int(diff.Seconds()) % 60

	var buf strings.Builder
	first := true

	addPart := func(value int, unit string) bool {
		if value == 0 {
			return false
		}
		if !first {
			buf.WriteString(", ")
		}
		buf.WriteString(strconv.Itoa(value))
		buf.WriteString(" ")
		buf.WriteString(unit)
		if value != 1 {
			buf.WriteString("s")
		}
		first = false
		return true
	}

	hasParts := false
	hasParts = addPart(days, "day") || hasParts
	hasParts = addPart(hours, "hour") || hasParts
	hasParts = addPart(minutes, "minute") || hasParts
	hasParts = addPart(seconds, "second") || hasParts

	if !hasParts {
		return "now"
	}

	buf.WriteString(" ago")
	return buf.String()
}

func parseTraffic(receive, transmit int64) string {
	buf := make([]byte, 0, 64)

	buf = customAppend(buf, float64(receive))
	buf = append(buf, " received, "...)

	buf = customAppend(buf, float64(transmit))
	buf = append(buf, " sent"...)

	return string(buf)
}

func customAppend(buf []byte, value float64) []byte {
	units := []string{"B", "KB", "MB", "GB", "TB"}

	for _, unit := range units {
		if value < 1024.0 || unit == "TB" {
			buf = strconv.AppendFloat(buf, value, 'f', 2, 64)
			buf = append(buf, ' ')
			buf = append(buf, unit...)
			return buf
		}
		value /= 1024.0
	}

	return buf
}

func main() {}
