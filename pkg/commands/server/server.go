package server

import (
	"github.com/urfave/cli/v2"

	"github.com/ekristen/oidc-zero/pkg/common"
	"github.com/ekristen/oidc-zero/pkg/config"
	"github.com/ekristen/oidc-zero/pkg/server"
)

func Execute(c *cli.Context) error {
	cfg, err := config.New(c.String("config"))
	if err != nil {
		return err
	}

	return server.RunServer(c.Context, &server.Options{
		Config: cfg,
		Port:   c.Int("port"),
		Issuer: c.String("issuer"),
	})
}

func init() {
	flags := []cli.Flag{
		&cli.IntFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Value:   4242,
		},
		&cli.PathFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Value:   "config.yaml",
		},
		&cli.StringFlag{
			Name:    "issuer",
			Aliases: []string{"i"},
		},
	}

	cmd := &cli.Command{
		Name:        "server",
		Usage:       "server",
		Description: "server",
		Before:      common.Before,
		Flags:       append(common.Flags(), flags...),
		Action:      Execute,
	}

	common.RegisterCommand(cmd)
}
