package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	IPv4LpmMapPinPath = "/sys/fs/bpf/siperipv4lpmmap"
	MetricsMapPinPath = "/sys/fs/bpf/sipermetricsmap"
	ProgramPinPath    = "/sys/fs/bpf/siperprogram"
)

const (
	METRICS_PASS = 0
	METRICS_DROP = 1
)

type IPv4LpmKey struct {
	PrefixLen uint32
	Data      uint32
}

type DataRec struct {
	Packets uint64
	Bytes   uint64
}

type SiperObjs struct {
	IPv4LpmMap       *ebpf.Map     `ebpf:"ipv4_lpm_map"`
	MetricsMap       *ebpf.Map     `ebpf:"metrics_map"`
	XDPSiperFirewall *ebpf.Program `ebpf:"xdp_siper_firewall"`
	Link             link.Link
}
