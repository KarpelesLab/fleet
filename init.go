package fleet

// perform init of various elements in order
func init() {
	initLog()
	initPath()
	initDb()
	initSeed()
	initAgent()
}

func Shutdown() {
	shutdownDb()
	shutdownLog()
}
