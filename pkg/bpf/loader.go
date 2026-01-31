package bpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (objs *SiperObjs) Close() error {
	if err := objs.IPv4LpmMap.Close(); err != nil {
		return err
	}
	if err := objs.MetricsMap.Close(); err != nil {
		return err
	}
	if err := objs.XDPSiperFirewall.Close(); err != nil {
		return err
	}

	return nil
}

func LoadProgram(objectName string, iface string) (*SiperObjs, error) {
	spec, err := ebpf.LoadCollectionSpec(objectName)
	if err != nil {
		return nil, err
	}

	var objs SiperObjs
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, err
	}

	l, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}

	fd := objs.XDPSiperFirewall.FD()
	if err := netlink.LinkSetXdpFdWithFlags(l, fd, 0); err != nil {
		if err2 := netlink.LinkSetXdpFdWithFlags(l, fd, int(unix.XDP_FLAGS_SKB_MODE)); err2 != nil {
			return nil, fmt.Errorf("attach native: %v; attach skb fallback: %w", err, err2)
		}
	}

	// link map and programs to persist
	if err := objs.IPv4LpmMap.Pin(IPv4LpmMapPinPath); err != nil {
		return nil, err
	}
	if err := objs.MetricsMap.Pin(MetricsMapPinPath); err != nil {
		return nil, err
	}
	if err := objs.XDPSiperFirewall.Pin(ProgramPinPath); err != nil {
		return nil, err
	}

	return &objs, nil
}

func UnloadProgram(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		return err
	}

	_ = os.Remove(ProgramPinPath)
	_ = os.Remove(IPv4LpmMapPinPath)
	_ = os.Remove(MetricsMapPinPath)

	return nil
}
