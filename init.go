package fleet

// perform init of various elements in order
func init() {
	initLog()
	initPath()
	initDb()
	initSeed()
	initAgent()
	go directoryThread()
}

func Shutdown() {
	shutdownDb()
	shutdownLog()
}
