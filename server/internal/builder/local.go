package builder

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type LocalBuilder struct {
	dockerClient *client.Client
}

func NewLocalBuilder() (*LocalBuilder, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}
	return &LocalBuilder{dockerClient: cli}, nil
}

func (b *LocalBuilder) Build(ctx context.Context, req *BuildRequest) (*BuildResult, error) {
	if err := b.ensureImage(ctx); err != nil {
		return nil, err
	}

	hostPayloadsPath := os.Getenv("HOST_PAYLOADS_PATH")
	if hostPayloadsPath == "" {
		hostPayloadsPath = "/app/payloads"
	}

	hostSharedPath := os.Getenv("HOST_SHARED_PATH")
	if hostSharedPath == "" {
		hostSharedPath = "/shared"
	}

	cfg := &container.Config{
		Image: "docker_builder:latest",
		Env:   req.EnvVars,
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: "host",
		Binds: []string{
			fmt.Sprintf("%s:/shared", hostSharedPath),
			fmt.Sprintf("%s/Darwin:/build/Darwin:ro", hostPayloadsPath),
			fmt.Sprintf("%s/Linux:/build/Linux:ro", hostPayloadsPath),
			fmt.Sprintf("%s/Windows:/build/Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/SMB_Windows:/build/SMB_Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Linux:/build/TCP_Linux:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Darwin:/build/TCP_Darwin:ro", hostPayloadsPath),
			fmt.Sprintf("%s/TCP_Windows:/build/TCP_Windows:ro", hostPayloadsPath),
			fmt.Sprintf("%s/shared:/build/shared:ro", hostPayloadsPath),
		},
	}

	resp, err := b.dockerClient.ContainerCreate(ctx, cfg, hostCfg, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create builder container: %v", err)
	}

	containerID := resp.ID
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := b.dockerClient.ContainerRemove(cleanupCtx, containerID, container.RemoveOptions{Force: true}); err != nil {
			log.Printf("[LocalBuilder] Warning: failed to remove container %s: %v", containerID, err)
		}
	}()

	waiter, err := b.dockerClient.ContainerAttach(ctx, containerID, container.AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
		Logs:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to builder container: %v", err)
	}
	defer waiter.Close()

	go func() {
		io.Copy(log.Writer(), waiter.Reader)
	}()

	if err := b.dockerClient.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start builder container: %v", err)
	}

	statusCh, errCh := b.dockerClient.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("builder container wait error: %v", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			logReader, _ := b.dockerClient.ContainerLogs(ctx, containerID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
			if logReader != nil {
				logs, _ := io.ReadAll(logReader)
				logReader.Close()
				return nil, fmt.Errorf("build failed with exit code %d: %s", status.StatusCode, string(logs))
			}
			return nil, fmt.Errorf("build failed with exit code %d", status.StatusCode)
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return &BuildResult{BinaryPath: fmt.Sprintf("/shared/%s", req.BinaryName)}, nil
}

func (b *LocalBuilder) ensureImage(ctx context.Context) error {
	_, _, err := b.dockerClient.ImageInspectWithRaw(ctx, "docker_builder:latest")
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Println("[LocalBuilder] Builder image not found, building...")
			cmd := exec.CommandContext(ctx, "docker", "compose", "build", "builder")
			cmd.Stdout = log.Writer()
			cmd.Stderr = log.Writer()
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to build builder image: %v", err)
			}
			return nil
		}
		return fmt.Errorf("error checking builder image: %v", err)
	}
	return nil
}
