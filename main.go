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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs dropperObjects
	if err := loadDropperObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

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

	for {
		select {
		case update, ok := <-ipCh:
			if !ok {
				log.Print("Input channel closed. Exiting.")
				stop()
				return
			}
			//TODO Handle no space left by resizing map
			if update.Sign == "+" {
				//TODO if you pass the same IP twice, the stats reset to 0! Make this idempotent.
				// Trie doesn't support ebpf.UpdateNoExist - it's treated as Any,
				// so instead we should store a rule ID here and use a separate map of ID:stats.
				err := objs.Ipv4LpmTrie.Put(update.Key, uint32(0))
				if err != nil {
					log.Fatal("Map put:", err)
				}
			} else if update.Sign == "-" {
				err := objs.Ipv4LpmTrie.Delete(update.Key)
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
		stats        = make(map[string]uint32)
		statsTick    = time.Tick(time.Second)
		statsKey     dropperIpv4LpmKey
		statsValue   uint32
		statsKeyAddr net.IP
		statsKeyCIDR net.IPNet
	)
	for {
		select {
		case <-statsTick:
			statsEntries := objs.Ipv4LpmTrie.Iterate()
			for statsEntries.Next(&statsKey, &statsValue) {
				statsKeyAddr = net.IPv4(byte(statsKey.Data), byte(statsKey.Data>>8), byte(statsKey.Data>>16), byte(statsKey.Data>>24))
				statsKeyCIDR = net.IPNet{IP: statsKeyAddr, Mask: net.CIDRMask(int(statsKey.Prefixlen), 32)}
				stats[statsKeyCIDR.String()] = statsValue
			}
			//TODO ship stats somewhere instead
			log.Println(stats)
		case <-ctx.Done():
			return
		}
	}
}
