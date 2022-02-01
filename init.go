package fleet

// perform init of various elements in order
func Init() {
	Agent.initLog()
	Agent.initPath()
	Agent.initDb()
	Agent.initSeed()
	Agent.directoryThread()
}

func Shutdown() {
	Agent.shutdownDb()
	Agent.shutdownLog()
}
