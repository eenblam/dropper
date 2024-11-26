package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type update struct {
	// Sign is either "+" or "-" for add and remove, rsp.
	Sign string
	Key  *dropperIpv4LpmKey
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	//TODO detect interface
	// Can I instead iterate over net.Interfaces(), then check for FlagUp,
	// then apply eBPF program to each such interface?
	// Right now I think they'd share the same counter object...
	// https://pkg.go.dev/net#Interface
	ifname := "wlp1s0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Remove resource limits for kernels <5.11.
	if err = rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs dropperObjects
	if err = loadDropperObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Connect tail program to jump table
	if err = objs.JmpTable.Put(uint32(0), objs.GetStats); err != nil {
		log.Fatalf("Failed to add stats collection to tail calls: %v", err)
	}

	// Attach program to interface.
	xdpDropLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropPacketsByIp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdpDropLink.Close()

	log.Printf("Dropping incoming packets on %s...", ifname)

	// 1-buffered channel to receive IPs from stdin.
	ipCh := make(chan *update, 1)
	go readStdinLines(ipCh)

	go pullStats(ctx, &objs)

	var statsKey uint64
	for {
		select {
		case update, ok := <-ipCh:
			if !ok {
				log.Print("Input channel closed. Exiting.")
				stop()
				return
			}
			statsKey = keyToUint64(update.Key)
			//TODO Handle no space left by resizing map
			if update.Sign == "+" {
				// UpdateNoExist is supported for a Hash. This way, we only create stats once.
				err = objs.DropStatsMap.Update(statsKey, uint64(0), ebpf.UpdateNoExist)
				if err != nil {
					log.Printf("StatsMap update: %s", err)
				}
				// LPM Trie doesn't support ebpf.UpdateNoExist - it's treated as Any,
				// so instead we should store a rule ID here and use a separate map of ID:stats.
				// (Currently, the rule is just a uint64 version of the key.)
				err = objs.Ipv4LpmTrie.Put(update.Key, statsKey)
				if err != nil {
					log.Fatal("Ipv4LpmTrie put:", err)
				}
			} else if update.Sign == "-" {
				err = objs.Ipv4LpmTrie.Delete(update.Key)
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					log.Printf("Key does not exist: %v", update.Key)
					continue
				} else if err != nil {
					log.Fatal("Map delete:", err)
				}
			} else {
				log.Fatalf("Invalid sign: %s", update.Sign)
			}
		case <-ctx.Done():
			log.Print("Received interrupt. Exiting.")
			stop()
			return
		}
	}
}

// readStdinLines reads and parses rules from stdin, and sends the resulting update over the channel.
// Channel ch should be 1-buffered so we can begin reading again with loose coupling.
func readStdinLines(ch chan<- *update) {
	reader := bufio.NewReader(os.Stdin)
	var sign string
	for {
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading from stdin: %s\n", err)
			close(ch)
			return
		}
		text = text[:len(text)-1]

		sign, text = text[:1], text[1:]
		if sign != "-" && sign != "+" {
			log.Printf("Invalid sign: [%s]", sign)
			continue
		}

		// Attempt to parse a single IPv4 address.
		if ip := net.ParseIP(text); ip != nil {
			log.Printf("Parsed IP: [%s]", ip)

			ch <- &update{
				Sign: sign,
				Key: &dropperIpv4LpmKey{
					Prefixlen: 32,
					// Convert to network byte order
					Data: binary.LittleEndian.Uint32(ip.To4()),
				},
			}
			continue
		}

		// Attempt to parse a CIDR block.
		if _, ipnet, err := net.ParseCIDR(text); err == nil {
			ip := ipnet.IP
			prefixLength, _ := ipnet.Mask.Size() // #ones, #bits
			log.Printf("Parsed CIDR: [%s/%d]", ip, prefixLength)
			ch <- &update{
				Sign: sign,
				Key: &dropperIpv4LpmKey{
					Prefixlen: uint32(prefixLength),
					// Convert to network byte order
					Data: binary.LittleEndian.Uint32(ip.To4()),
				},
			}
			continue
		}

		log.Printf("Failed to parse IP or CIDR: [%s]", text)
	}

}

// pullStats periodically reads the stats from the eBPF map and logs them.
func pullStats(ctx context.Context, objs *dropperObjects) {
	var (
		stats      = make(map[string]uint64)
		statsTick  = time.Tick(time.Second)
		statsKey   uint64
		statsValue uint64
		statsRule  net.IPNet
	)
	for {
		select {
		case <-statsTick:
			statsEntries := objs.DropStatsMap.Iterate()
			for statsEntries.Next(&statsKey, &statsValue) {
				statsRule = uint64ToIpNet(statsKey)
				stats[statsRule.String()] = statsValue
			}
			//TODO ship stats somewhere instead
			log.Println(stats)
		case <-ctx.Done():
			return
		}
	}
}

// keyToIp converts an LPM key into a net.IP.
func keyToIp(key *dropperIpv4LpmKey) net.IP {
	return net.IPv4(byte(key.Data), byte(key.Data>>8), byte(key.Data>>16), byte(key.Data>>24))
}

// keyToUint64 converts an LPM key (a struct of two uint32's) into a uint64.
// An LPM key is two uint32s for the IPv4 and the prefix length.
// This just stores the IPv4 in the high bits of a uint64,
// and the prefix length in the low bits.
func keyToUint64(key *dropperIpv4LpmKey) uint64 {
	return (uint64(key.Data) << 32) | uint64(key.Prefixlen)
}

// uint64ToIpNet uses the high bits of a uint64 as a network address
// and the low bits as a prefix length in order to produce a net.IPNet.
func uint64ToIpNet(x uint64) net.IPNet {
	addr := net.IPv4(byte(x>>32), byte(x>>40), byte(x>>48), byte(x>>56))
	return net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(int(uint32(x)), 32),
	}
}
