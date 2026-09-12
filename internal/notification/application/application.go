package application

type Dependency struct {
}

type Application struct {
}

func New(dep Dependency) *Application {
	return &Application{}
}
