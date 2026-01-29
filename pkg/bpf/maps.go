package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

func CreateKey(cidr string) (*IPv4LpmKey, error) {
	var key IPv4LpmKey

	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ipv4 := ipnet.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("not IPv4: %s ", cidr)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("unexpected mask bits: %d", bits)
	}

	netIP := ipv4.Mask(ipnet.Mask)
	data := binary.BigEndian.Uint32(netIP)

	key.PrefixLen = uint32(ones)
	key.Data = data

	return &key, nil
}

func (objs *SiperObjs) AddCidr(key *IPv4LpmKey) error {
	var value uint32 = 1

	err := objs.IPv4LpmMap.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (objs *SiperObjs) DelCidr(key *IPv4LpmKey) error {
	err := objs.IPv4LpmMap.Delete(key)
	if err != nil {
		return err
	}

	return nil
}

func (objs *SiperObjs) ReadMetrics(metricType uint32) (*DataRec, error) {
	var records []DataRec

	err := objs.MetricsMap.Lookup(metricType, &records)
	if err != nil {
		return nil, err
	}

	var total DataRec
	for _, rec := range records {
		total.Packets += rec.Packets
		total.Bytes += rec.Bytes
	}

	return &total, nil
}
