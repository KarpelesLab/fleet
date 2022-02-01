package fleet

type sortablePeers []*Peer

func (s sortablePeers) Len() int {
	return len(s)
}

func (s sortablePeers) Less(i, j int) bool {
	return s[i].name < s[j].name
}

func (s sortablePeers) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
