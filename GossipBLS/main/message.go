package main

func (self *message) copy() *message {
	ret := message{}
	ret.sum = self.sum
	ret.aggSig = self.aggSig.NewFieldElement().Set(self.aggSig)
	ret.counters = make([]int, numPeers)
	for i := 0; i < numPeers; i++ {
		ret.counters[i] = self.counters[i]
	}
	return &ret
}
