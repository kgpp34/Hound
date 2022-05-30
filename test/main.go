package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"

	bpf "github.com/aquasecurity/libbpfgo"
)

type cdata struct {
	HostPid  uint32
	HostPpid uint32

	Sport uint16
	Dport uint16

	Saddr [4]uint8
	Daddr [4]uint8
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

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()
	if err := resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("tracepoint__tcp__tcp_retransmit_skb")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachTracepoint("tcp", "tcp_retransmit_skb"); err != nil {
		panic(err)
	}

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
			var cd cdata
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(e)
			err = binary.Read(dataBuffer, binary.LittleEndian, &cd)
			if err != nil {
				log.Println(err)
				continue
			}

			sourceIp := binary.BigEndian.Uint32(cd.Saddr[:])
			saddr, err := Long2IPString(uint(sourceIp))
			if err != nil {
				log.Println(err)
			}
			destIp := binary.BigEndian.Uint32(cd.Daddr[:])
			daddr, err := Long2IPString(uint(destIp))
			if err != nil {
				log.Println(err)
			}

			log.Printf(`HostPid: %d, HostPpid: %d occured tcp retransmit, sport: %d, dport: %d, saddr %s ->  daddr %s `,
				cd.HostPid, cd.HostPpid, cd.Sport, cd.Dport, saddr, daddr)
		}
	}
}
