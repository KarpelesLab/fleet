package fleet

// perform init of various elements in order
func Init() {
	initLog()
	initPath()
	initDb()
	initSeed()
	go directoryThread()
}

func Shutdown() {
	shutdownDb()
	shutdownLog()
}
