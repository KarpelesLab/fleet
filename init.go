package fleet

// perform init of various elements in order
func init() {
	initPath()
	initLog()
	initSeed()
	initAgent()
}
