package stream

func WindowBucket(bytes int) string {
	switch {
	case bytes <= 0:
		return "blocked"
	case bytes <= 16*1024:
		return "low"
	case bytes <= 64*1024:
		return "medium"
	default:
		return "high"
	}
}

func PriorityClass(priority string) string {
	switch priority {
	case "interactive":
		return "interactive"
	case "bulk":
		return "bulk"
	case "":
		return "bulk"
	default:
		return "other"
	}
}
