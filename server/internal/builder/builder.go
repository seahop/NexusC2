package builder

import "context"

type BuildRequest struct {
	EnvVars    []string
	BinaryName string
}

type BuildResult struct {
	BinaryPath string
}

type Builder interface {
	Build(ctx context.Context, req *BuildRequest) (*BuildResult, error)
}
