package bpf

import (
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
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
	if err := objs.Link.Close(); err != nil {
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

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	opts := link.XDPOptions{
		Program:   objs.XDPSiperFirewall,
		Interface: ifaceObj.Index,
		Flags:     link.XDPGenericMode,
	}

	// XXX
	// it looks like it does not attach the program to specified interface
	// maybe because of the opts (especially opts.Interface), or the function
	// that loads the program (AttachXDP)
	l, err := link.AttachXDP(opts)
	if err != nil {
		_ = objs.Close()
		return nil, err
	}
	objs.Link = l

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

	linkAttrs := link.Attrs()
	if linkAttrs.Name == ProgramPinPath {
		if err := netlink.LinkSetXdpFd(link, -1); err != nil {
			return err
		}
	}

	_ = os.Remove(ProgramPinPath)
	_ = os.Remove(IPv4LpmMapPinPath)
	_ = os.Remove(MetricsMapPinPath)

	return nil
}
