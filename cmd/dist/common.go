package main

import (
	"net"
	"path/filepath"
	"time"

	"github.com/docker/containerd/content"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
)

func resolveContentStore(context *cli.Context) (*content.Store, error) {
	root := context.GlobalString("root")
	if !filepath.IsAbs(root) {
		var err error
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, err
		}
	}
	return content.NewStore(root)
}

func connectGRPC(context *cli.Context) (*grpc.ClientConn, error) {
	socket := context.GlobalString("socket")
	return grpc.Dial(socket,
		grpc.WithBlock(),
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socket, timeout)
		}),
	)
}