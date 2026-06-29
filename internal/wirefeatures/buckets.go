// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

func BucketFromFixtureBucket(bucket string) string {
	switch bucket {
	case "zero":
		return "size_0"
	case "tiny":
		return "size_17_32"
	case "small":
		return "size_65_128"
	case "medium":
		return "size_129_512"
	case "large":
		return "size_1501_4096"
	default:
		if validSizeBucket(bucket) {
			return bucket
		}
		return "size_129_512"
	}
}

func CountBucket(value int) string {
	switch {
	case value <= 0:
		return "count_0"
	case value == 1:
		return "count_1"
	case value <= 3:
		return "count_2_3"
	case value <= 8:
		return "count_4_8"
	default:
		return "count_9_plus"
	}
}

func validSizeBucket(bucket string) bool {
	for _, value := range []string{"size_0", "size_1_3", "size_4_8", "size_9_16", "size_17_32", "size_33_64", "size_65_128", "size_129_512", "size_513_1500", "size_1501_4096", "size_4097_plus"} {
		if bucket == value {
			return true
		}
	}
	return false
}
