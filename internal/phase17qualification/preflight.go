// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"kurdistan/internal/assurance"
)

const OwnerVPSPreflightSchema = "kurdistan-phase17-owned-vps-preflight-v1"

type OwnerVPSPreflight struct {
	Schema            string `json:"schema"`
	PreflightID       string `json:"preflightId"`
	EnvironmentSHA256 string `json:"environmentSha256"`
	Status            string `json:"status"`
	HostClass         string `json:"hostClass"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	Systemd           bool   `json:"systemd"`
	Networkd          bool   `json:"networkd"`
	NFT               bool   `json:"nft"`
	Unbound           bool   `json:"unbound"`
	TUN               bool   `json:"tun"`
	TimeSynchronized  bool   `json:"timeSynchronized"`
	HostClockToVPS    bool   `json:"hostClockToVps"`
	Memory            bool   `json:"memory"`
	Disk              bool   `json:"disk"`
	IPv4              bool   `json:"ipv4"`
	IPv6              bool   `json:"ipv6"`
	IPv6Global        bool   `json:"ipv6Global"`
	IPv6DefaultRoute  bool   `json:"ipv6DefaultRoute"`
	IPv6Forwarding    bool   `json:"ipv6Forwarding"`
	IPv6NFTPolicy     bool   `json:"ipv6NftPolicy"`
	IPv6External      bool   `json:"ipv6External"`
	Sudo              bool   `json:"sudo"`
	RawLogRetained    bool   `json:"rawLogRetained"`
}

func VerifyOwnerVPSPreflight(raw []byte, environmentSHA256 string) (string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !hex64Pattern.MatchString(environmentSHA256) {
		return "", errors.New("qualification owner-VPS preflight input rejected")
	}
	var value OwnerVPSPreflight
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &value); err != nil {
		return "", errors.New("qualification owner-VPS preflight document rejected")
	}
	if err := ValidateOwnerVPSPreflight(value, environmentSHA256); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateOwnerVPSPreflight(value OwnerVPSPreflight, environmentSHA256 string) error {
	if value.Schema != OwnerVPSPreflightSchema || !hex32Pattern.MatchString(value.PreflightID) ||
		value.EnvironmentSHA256 != environmentSHA256 || value.Status != "PASS" || value.HostClass != "OWNER_CONTROLLED_VPS" ||
		value.OS != "linux" || value.Arch != "amd64" || !value.Systemd || !value.Networkd || !value.NFT || !value.Unbound ||
		!value.TUN || !value.TimeSynchronized || !value.HostClockToVPS || !value.Memory || !value.Disk || !value.IPv4 ||
		!value.Sudo || value.RawLogRetained {
		return errors.New("qualification owner-VPS preflight result rejected")
	}
	ipv6Ready := value.IPv6Global && value.IPv6DefaultRoute && value.IPv6Forwarding && value.IPv6NFTPolicy && value.IPv6External
	if value.IPv6 != ipv6Ready {
		return errors.New("qualification owner-VPS IPv6 preflight is inconsistent")
	}
	return nil
}
