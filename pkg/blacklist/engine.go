package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

func CreateBlacklist(version string) *Blacklist {
	currentTime := time.Now().UTC().String()
	return &Blacklist{
		Version:   version,
		CreatedAt: currentTime,
		UpdatedAt: currentTime,
		Rules:     []Rule{},
	}
}

func GenerateID() string {
	return ulid.Make().String()
}

func CanonicalizeCidr(cidr string) (string, error) {
	split := strings.Split(cidr, "/")
	dotted := split[0]
	size, err := strconv.Atoi(split[1])
	if err != nil {
		return "", fmt.Errorf("atoi: %w", err)
	}

	var bin []string
	for _, n := range strings.Split(dotted, ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			return "", fmt.Errorf("canonicalize: %w", err)
		}

		bin = append(bin, fmt.Sprintf("%08b", i))
	}
	binary := strings.Join(bin, "")

	binary = binary[0:size] + strings.Repeat("0", 32-size)

	var canon []string
	for i := 0; i < len(binary); i += 8 {
		num, err := strconv.ParseInt(binary[i:i+8], 2, 64)
		if err != nil {
			return "", fmt.Errorf("canonicalize: %w", err)
		}

		canon = append(canon, fmt.Sprintf("%d", num))
	}

	return strings.Join(canon, ".") + "/" + split[1], nil
}

func (b *Blacklist) AddCidr(cidr string, source string, comment string, enabled bool) (*Rule, error) {
	canon, err := CanonicalizeCidr(cidr)
	if err != nil {
		return nil, err
	}
	r := Rule{
		ID:        GenerateID(),
		Cidr:      canon,
		Family:    "ipv4", // Only IPv4 Supported for now
		Enabled:   enabled,
		Source:    source,
		Comment:   comment,
		CreatedAt: time.Now().UTC().String(),
	}

	b.Rules = append(b.Rules, r)
	b.UpdatedAt = time.Now().UTC().String()

	return &r, nil
}

func (b *Blacklist) DeleteByCidr(cidr string) error {
	if len(b.Rules) == 0 {
		return fmt.Errorf("blacklist is empty")
	}

	for i, rule := range b.Rules {
		if rule.Cidr == cidr {
			b.Rules = slices.Delete(b.Rules, i, i+1)
			return nil
		}
	}

	return fmt.Errorf("cidr not found in blacklist: %s", cidr)
}

func (b *Blacklist) DeleteByID(ID string) error {
	if len(b.Rules) == 0 {
		return fmt.Errorf("blacklist is empty")
	}

	for i, rule := range b.Rules {
		if rule.ID == ID {
			b.Rules = slices.Delete(b.Rules, i, i+1)
			return nil
		}
	}

	return fmt.Errorf("ID not found in blacklist: %s", ID)
}

func (b *Blacklist) WriteBlacklist(path string) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "blacklist-*.json")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	JsonBlacklist, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return fmt.Errorf("marshal blacklist: %w", err)
	}

	if _, err := tmp.Write(JsonBlacklist); err != nil {
		return fmt.Errorf("write temp blacklist: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temp blacklist: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp blacklist: %w", err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("atomic renamce blacklist: %w", err)
	}

	return nil
}

func LoadBlacklist(path string) (*Blacklist, error) {
	var b Blacklist

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}

	if dec.More() {
		return nil, fmt.Errorf("trailing JSON data in %s", path)
	}

	return &b, nil
}
