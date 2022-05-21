package main

import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"

	bpf "github.com/aquasecurity/libbpfgo"
	// "github.com/thinkeridea/go-extend/exnet"
)

type sessionUserData struct {
	Saddr uint32
	Daddr uint32
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func Long2IPString(i uint) (string, error) {
	if i > math.MaxUint32 {
		return "", errors.New("beyond the scope of ipv4")
	}

	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(i >> 24)
	ip[1] = byte(i >> 16)
	ip[2] = byte(i >> 8)
	ip[3] = byte(i)

	return ip.String(), nil
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	fmt.Println("load .o file success")

	defer bpfModule.Close()
	if err := resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	fmt.Println("load object success")

	prog1, err := bpfModule.GetProgram("kprobe__tcp_v4_connect")
	if err != nil {
		panic(err)
	}
	fmt.Println("load kprobe prog success")
	prog2, err := bpfModule.GetProgram("kretprobe__tcp_v4_connect")
	if err != nil {
		panic(err)
	}
	fmt.Println("load kretprobe prog success")
	if _, err := prog1.AttachKprobe("tcp_v4_connect"); err != nil {
		panic(err)
	}
	fmt.Println("attach tcp_v4_connect() kretprobe success")
	if _, err := prog2.AttachKretprobe("tcp_v4_connect"); err != nil {
		panic(err)
	}
	fmt.Println("attach tcp_v4_connect() kretprobe success")

	eventsChannel := make(chan []byte)
	pb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		panic(err)
	}

	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	for {
		select {
		case e := <-eventsChannel:
			saddr := binary.LittleEndian.Uint32(e[0:4])
			daddr := binary.LittleEndian.Uint32(e[4:])

			srcIp, _ := Long2IPString(uint(saddr))
			destIp, _ := Long2IPString(uint(daddr))

			log.Printf("session connect established, src: %s dest: %s", srcIp, destIp)
		}
	}
}
