package stream

func IsTerminal(state State) bool {
	return state == StateClosed || state == StateReset
}
