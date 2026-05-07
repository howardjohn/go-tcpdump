package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/howardjohn/log-helper/pkg/color"
)

const (
	SNAPSHOTLENGTH int32         = 65535                 // Snapshot length
	PROMISCUOUS    bool          = false                 // Promiscuous mode
	TIMEOUT        time.Duration = time.Millisecond * 20 // Timeout
)

var (
	numpackets       int    = 0
	outputfile       string = ""
	packetstocapture int    = 0
	packetfilter     string = ""
)

type Devices struct {
	devices []Device
}

type Device struct {
	ID          int
	Name        string
	Description string
	MAC         net.HardwareAddr
	Addresses   []Addrs
}

type Addrs struct {
	IP      net.IP
	Netmask net.IPMask
}

// Set the BPF filter
func SetPacketFilter(f string) {
	packetfilter = f
}

// Set thefilename to save the data to
func SetSaveFile(f string) {
	outputfile = f
}

// Set the number of packets you want to capture
func SetPacketsToCapture(n int) {
	packetstocapture = n
}

// Get the mac address of the provided device
func GetMac(device string) net.HardwareAddr {
	var hw net.HardwareAddr = nil

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("error with interfaces")
	}

	for _, iface := range ifaces {
		if iface.Name == device {
			return iface.HardwareAddr
		}
	}
	return hw
}

// Get a list of all network interfaces
func GetAllDevices() (Devices, error) {
	// Setup Devices struct
	devicesStruct := Devices{}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return devicesStruct, errors.New("error getting all devices")
	}

	// Loop through each device
	id := 1
	for _, device := range devices {
		// Create new Device
		d := Device{}
		d.ID = id
		d.Name = device.Name
		mac := GetMac(device.Name)
		d.MAC = mac

		for _, address := range device.Addresses {
			a := Addrs{IP: address.IP, Netmask: address.Netmask}
			d.Addresses = append(d.Addresses, a)
		}

		// Add to list
		devicesStruct.devices = append(devicesStruct.devices, d)
		id++
	}

	return devicesStruct, nil
}

// Print all devices and their details
func (d *Devices) PrintAllDevices() error {
	for _, dev := range d.devices {
		// Do not print if there are no addressses
		if len(dev.Addresses) != 0 {
			fmt.Printf("ID: %d\n", dev.ID)
			fmt.Printf("Name: %s\n", dev.Name)
			fmt.Printf("MAC: %s\n", dev.MAC.String())
			fmt.Println("Devices addresses: ")
			for _, address := range dev.Addresses {
				fmt.Printf("\tIP address: %s\n", address.IP.String())
				addr := net.IP(address.Netmask).String()
				fmt.Printf("\tSubnet mask: %s\n", addr)
			}
			fmt.Println()
		}
	}

	return nil
}

func (d *Devices) GetDevice(s string) (Device, error) {
	retDev := Device{}

	for _, dev := range d.devices {
		if dev.Name == s || strconv.Itoa(dev.ID) == s {
			return dev, nil
		}
	}

	return retDev, errors.New("error finding device")
}

var variants = []float64{0, 0.5, -0.25, 0.25, 0.75, -0.375, -0.125}

type Color struct {
	last     int
	variants map[string]int
	colors    []color.Color
}

func (m *Color) Color(data string) string {
	return  m.ColorFor(data).Sprint(data)
}
func (m *Color) ColorFor(data string) color.Color {
	iter, f := m.variants[data]
	if !f {
		m.variants[data] = m.last
		iter = m.last
		m.last++
	}
	col := m.colors[iter%len(m.colors)]
	adj := iter/len(m.colors)
	return color.Adjust(col, variants[adj%len(variants)])
}

func printPacket(c *Color, p gopacket.Packet) {
	// Variables we want to print
	var src_ip string
	var src_port string
	var des_ip string
	var des_port string
	var proto string
	sendtime := formatDate(p.Metadata().Timestamp)
	packetlength := p.Metadata().Length
	var payload []byte
	var mode []string
	// Check if it is IPv6
	ip6Layer := p.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		src_ip = ip.SrcIP.String()
		des_ip = ip.DstIP.String()
	}

	// Check if it is IPv4
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src_ip = ip.SrcIP.String()
		des_ip = ip.DstIP.String()
	}

	// If src_ip is blank then it was an ethernet packet (layer 2) probably
	if src_ip == "" {
		// Get Ethernet layer
		ethLayer := p.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			src_ip = eth.SrcMAC.String()
			des_ip = eth.DstMAC.String()
			proto = "ETH"
		}
	}

	// Check if it is UDP
	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		src_port = strconv.Itoa(int(udp.SrcPort))
		des_port = strconv.Itoa(int(udp.DstPort))
		proto = "UDP"
		payload = udp.Payload
	}

	// Check if it is TCP
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		src_port = strconv.Itoa(int(tcp.SrcPort))
		des_port = strconv.Itoa(int(tcp.DstPort))
		proto = "TCP"
		payload = tcpLayer.LayerPayload()
		if tcp.FIN {
			mode = append(mode, "FIN")
		}
		if tcp.SYN {
			mode = append(mode, "SYN")
		}
		if tcp.RST {
			mode = append(mode, "RST")
		}
		if tcp.PSH {
			mode = append(mode, "PSH")
		}
		if tcp.ACK {
			mode = append(mode, "ACK")
		}
	}

	// Check if it is ARP
	arpLayer := p.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		proto = "ARP"
	}

	// Check if it is PING
	ping4Layer := p.Layer(layers.LayerTypeICMPv4)
	if ping4Layer != nil {
		proto = "ICMP"
	}
	ping6Layer := p.Layer(layers.LayerTypeICMPv4)
	if ping6Layer != nil {
		proto = "ICMP"
	}

	// Print out the details if there is a port associated
	var o string
	if src_port != "" {
		ms := ""
		if mode != nil {
			ms = " (" + strings.Join(mode, ",") + ")"
		}
		o = fmt.Sprintf("%s %s %s --> %s (len:%d)%s", sendtime, proto, c.Color(src_ip + ":" + src_port), c.Color(des_ip + ":" + des_port), packetlength, ms)
	} else {
		o = fmt.Sprintf("%s %s %s --> %s (len:%d)", sendtime, proto, src_ip, des_ip, packetlength)
	}
	if payload != nil {
		o += fmt.Sprintf("\n%v", string(payload))
	}

	fmt.Println(o)
}

// Start capturing packets
func (d *Device) Start() {
	// If user wants to save the data to a file
	var w *pcapgo.Writer
	if outputfile != "" {
		// Open output pcap file and write header
		f, _ := os.Create(outputfile)
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(uint32(SNAPSHOTLENGTH), layers.LinkTypeEthernet)
		defer f.Close()
	}

	// Open the device for capturing
	handler, err := pcap.OpenLive(d.Name, SNAPSHOTLENGTH, PROMISCUOUS, TIMEOUT)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	// Set filter if one was provided
	if packetfilter != "" {
		err := handler.SetBPFFilter(packetfilter)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Start processing packets
	source := gopacket.NewPacketSource(handler, handler.LinkType())

	cc := &Color{
		last:     0,
		variants: make(map[string]int),
		colors:    []color.Color{
			color.Hex(`#cb4b16`),
			color.Hex(`#a2ba00`),
			color.Hex(`#e1ab00`),
			color.Hex(`#0096ff`),
			color.Hex(`#6c71c4`),
			color.Hex(`#31bbb0`),
		},
	}
	for packet := range source.Packets() {
		// Increase the number of packets we have processed
		numpackets++

		// Print details of the packet
		printPacket(cc, packet)

		// Check if we should write the packe to disk
		if outputfile != "" {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		// Break if we captured all the packets we wanted
		if packetstocapture != 0 && numpackets >= packetstocapture {
			log.Printf("Done capturing %d packets\n", packetstocapture)
			break
		}
	}

}

func formatDate(t time.Time) string {
	t = t.UTC()
	year, month, day := t.Date()
	hour, minute, second := t.Clock()
	micros := t.Nanosecond() / 1000

	buf := make([]byte, 27)

	buf[0] = byte((year/1000)%10) + '0'
	buf[1] = byte((year/100)%10) + '0'
	buf[2] = byte((year/10)%10) + '0'
	buf[3] = byte(year%10) + '0'
	buf[4] = '-'
	buf[5] = byte((month)/10) + '0'
	buf[6] = byte((month)%10) + '0'
	buf[7] = '-'
	buf[8] = byte((day)/10) + '0'
	buf[9] = byte((day)%10) + '0'
	buf[10] = 'T'
	buf[11] = byte((hour)/10) + '0'
	buf[12] = byte((hour)%10) + '0'
	buf[13] = ':'
	buf[14] = byte((minute)/10) + '0'
	buf[15] = byte((minute)%10) + '0'
	buf[16] = ':'
	buf[17] = byte((second)/10) + '0'
	buf[18] = byte((second)%10) + '0'
	buf[19] = '.'
	buf[20] = byte((micros/100000)%10) + '0'
	buf[21] = byte((micros/10000)%10) + '0'
	buf[22] = byte((micros/1000)%10) + '0'
	buf[23] = byte((micros/100)%10) + '0'
	buf[24] = byte((micros/10)%10) + '0'
	buf[25] = byte((micros)%10) + '0'
	buf[26] = 'Z'

	return string(buf)
}
