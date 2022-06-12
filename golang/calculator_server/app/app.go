package app

type App struct {
	xchgService *XchgService
}

func NewApp() *App {
	var c App
	c.xchgService = NewXchgService()
	return &c
}

func (c *App) Start() {
	c.xchgService.Start()
}
