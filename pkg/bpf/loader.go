package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
		_ = objs.Close()
		return nil, err
	}

	opts := link.XDPOptions {
		Program: objs.XDPSiperFirewall,
		Interface: ifaceObj.Index,
		Flags: link.XDPGenericMode,
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		_ = objs.Close()
		return nil, err
	}
	objs.Link = l

	return &objs, nil
}
