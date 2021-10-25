package fleet

// perform init of various elements in order
func Init() {
	initLog()
	initPath()
	initDb()
	initSeed()
	directoryThread()
}

func Shutdown() {
	shutdownDb()
	shutdownLog()
}
