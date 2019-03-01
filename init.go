package fleet

// perform init of various elements in order
func init() {
	initLog()
	initPath()
	initSeed()
	initAgent()
}

func Shutdown() {
	shutdownDb()
	shutdownLog()
}
