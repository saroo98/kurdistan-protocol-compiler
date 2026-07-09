// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import "fmt"

type PacketDirection string

const (
	DirectionClientToServer PacketDirection = "c2s"
	DirectionServerToClient PacketDirection = "s2c"
)

type PacketShape struct {
	Index      int             `json:"index"`
	Direction  PacketDirection `json:"direction"`
	SizeBucket string          `json:"size_bucket"`
	KindBucket string          `json:"kind_bucket"`
	Final      bool            `json:"final"`
	Reset      bool            `json:"reset"`
	Control    bool            `json:"control"`
}

type FirstNPacketShape struct {
	N              int           `json:"n"`
	Packets        []PacketShape `json:"packets"`
	DirectionClass string        `json:"direction_class"`
	SizeClass      string        `json:"size_class"`
	Hash           string        `json:"hash"`
}

func NewFirstNShape(packets []PacketShape) (FirstNPacketShape, error) {
	shape := FirstNPacketShape{N: len(packets), Packets: append([]PacketShape(nil), packets...)}
	if err := ValidateFirstNShape(shape); err != nil {
		return FirstNPacketShape{}, err
	}
	shape.DirectionClass = directionClass(packets)
	shape.SizeClass = sizeClass(packets)
	hash, err := HashValue(struct {
		Packets        []PacketShape `json:"packets"`
		DirectionClass string        `json:"direction_class"`
		SizeClass      string        `json:"size_class"`
	}{shape.Packets, shape.DirectionClass, shape.SizeClass})
	if err != nil {
		return FirstNPacketShape{}, err
	}
	shape.Hash = hash
	return shape, nil
}

func ValidateFirstNShape(shape FirstNPacketShape) error {
	if shape.N != len(shape.Packets) {
		return fmt.Errorf("%w: packet count mismatch", ErrInvalidFeature)
	}
	if shape.N > 16 {
		return fmt.Errorf("%w: too many first-n packets", ErrInvalidFeature)
	}
	for i, packet := range shape.Packets {
		if packet.Index != i {
			return fmt.Errorf("%w: packet index %d", ErrInvalidFeature, packet.Index)
		}
		if packet.Direction != DirectionClientToServer && packet.Direction != DirectionServerToClient {
			return fmt.Errorf("%w: packet direction %s", ErrInvalidFeature, packet.Direction)
		}
		if !validSizeBucket(packet.SizeBucket) {
			return fmt.Errorf("%w: packet size bucket %s", ErrInvalidFeature, packet.SizeBucket)
		}
		if !safeToken(packet.KindBucket) {
			return fmt.Errorf("%w: packet kind bucket", ErrInvalidFeature)
		}
	}
	return nil
}

func directionClass(packets []PacketShape) string {
	if len(packets) == 0 {
		return "unknown"
	}
	first := packets[0].Direction
	allSame := true
	for _, packet := range packets[1:] {
		if packet.Direction != first {
			allSame = false
			break
		}
	}
	if allSame && first == DirectionClientToServer {
		return "client_burst"
	}
	if allSame && first == DirectionServerToClient {
		return "server_burst"
	}
	return "bidirectional_interleaved"
}

func sizeClass(packets []PacketShape) string {
	if len(packets) == 0 {
		return "unknown"
	}
	large := 0
	for _, packet := range packets {
		if packet.SizeBucket == "size_513_1500" || packet.SizeBucket == "size_1501_4096" || packet.SizeBucket == "size_4097_plus" {
			large++
		}
	}
	if large == 0 {
		return "small"
	}
	if large == len(packets) {
		return "large"
	}
	return "mixed"
}
