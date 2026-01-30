package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/fksvs/siper/pkg/blacklist"
	"github.com/fksvs/siper/pkg/bpf"
)

// this struct holds values for run command
type RunOptions struct {
	Iface         string
	BlacklistPath string
	ObjectPath    string
	DryRun        bool
}

// this struct holds values for add and del commands
type KeyOptions struct {
	BlacklistPath string
	ID            string
	Cidr          string
	Comment       string
	Source        string
}

func usage() {
	// TODO
	fmt.Printf("Usage here\n")
	os.Exit(2)
}

func runCmd(commands []string) {
	var RunVars RunOptions

	fs := flag.NewFlagSet("siper", flag.ExitOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&RunVars.Iface, "iface", "", "Network Interface [Required]")
	fs.StringVar(&RunVars.BlacklistPath, "path", "./blacklist.json", "Path to Blacklist File [Required]")
	fs.StringVar(&RunVars.ObjectPath, "object", "./siper.o", "Path to XDP object [Required]")
	fs.BoolVar(&RunVars.DryRun, "dry-run", false, "Dry run")
	fs.Parse(commands)

	// check if we got all required commands
	if RunVars.Iface == "" {
		fmt.Printf("interface required to load XDP program\n")
		os.Exit(2)
	}

	if RunVars.DryRun == true {
		fmt.Printf("Dry-run started\n")
		// TODO
		os.Exit(2)
	}

	b, err := blacklist.LoadBlacklist(RunVars.BlacklistPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Blacklist JSON file readed\n")

	SiperObjs, err := bpf.LoadProgram(RunVars.ObjectPath, RunVars.Iface)
	if err != nil {
		panic(err)
	}
	fmt.Printf("XDP Program loaded to kernel and attached to %s\n", RunVars.Iface)

	for _, v := range b.Rules {
		key, err := bpf.CreateKey(v.Cidr)
		if err != nil {
			panic(err)
		}

		err = SiperObjs.AddCidr(key)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("Keys added to eBPF map\n")
}

func stopCmd(commands []string) {
	var RunVars RunOptions

	fs := flag.NewFlagSet("siper", flag.ExitOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&RunVars.Iface, "iface", "", "Network Interface [Required]")
	fs.Parse(commands)

	if RunVars.Iface == "" {
		fmt.Printf("interface required to stop siper\n")
		os.Exit(2)
	}

	if err := bpf.UnloadProgram(RunVars.Iface); err != nil {
		panic(err)
	}
}

func dumpMetricsCmd(commands []string) {
	totalDrops, err := bpf.ReadMetrics(bpf.METRICS_DROP)
	if err != nil {
		panic(err)
	}

	totalPass, err := bpf.ReadMetrics(bpf.METRICS_PASS)
	if err != nil {
		panic(err)
	}

	fmt.Printf("DROPS\n")
	fmt.Printf("Packets: %d\n", totalDrops.Packets)
	fmt.Printf("Bytes: %d\n", totalDrops.Bytes)

	fmt.Printf("PASSES\n")
	fmt.Printf("Packets: %d\n", totalPass.Packets)
	fmt.Printf("Bytes: %d\n", totalPass.Bytes)
}

func dumpKeysCmd(commands []string) {}

func addKeysCmd(commands []string) {
	var AddVars KeyOptions

	fs := flag.NewFlagSet("siper", flag.ExitOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&AddVars.BlacklistPath, "path", "./blacklist.json", "Path to Blacklist File [Required]")
	fs.StringVar(&AddVars.Cidr, "cidr", "", "CIDR [Required]")
	fs.StringVar(&AddVars.Comment, "comment", "", "Comment for the key")
	fs.StringVar(&AddVars.Source, "source", "", "Source for the key")
	fs.Parse(commands)

	if AddVars.Cidr == "" {
		fmt.Printf("CIDR is empty\n")
		os.Exit(2)
	}

	b, err := blacklist.LoadBlacklist(AddVars.BlacklistPath)
	if err != nil {
		b = blacklist.CreateBlacklist("1")
	}

	b.AddCidr(AddVars.Cidr, AddVars.Source, AddVars.Comment, true)

	err = b.WriteBlacklist(AddVars.BlacklistPath)
	if err != nil {
		panic(err)
	}
}

func delKeysCmd(commands []string) {}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "stop":
		stopCmd(os.Args[2:])
	case "add":
		addKeysCmd(os.Args[2:])
	case "del":
		delKeysCmd(os.Args[2:])
	case "dump-keys":
		dumpKeysCmd(os.Args[2:])
	case "dump-metrics":
		dumpMetricsCmd(os.Args[2:])
	case "help":
		usage()
		os.Exit(2)
	default:
		usage()
		os.Exit(2)
	}
}
