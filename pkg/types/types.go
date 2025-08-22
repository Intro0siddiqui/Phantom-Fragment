package types

type Container struct {
	ID            string
	Workdir       string
	Binds         []string
	Env           map[string]string
	SeccompProfile string
}
