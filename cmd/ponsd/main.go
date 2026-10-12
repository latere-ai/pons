// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Command ponsd keeps people's connections to other services, seals each
// credential, and carries every call to the other service, so no caller
// holds a credential. It takes one command and no flag, and is configured
// by its environment (specs/011-distribution.md):
//
//	ponsd serve    serve until a signal
//	ponsd check    read the configuration as serve would, serve nothing
//	ponsd version  print the version, the commit and the date of the build
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"latere.ai/x/pons/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ponsd:", err)
		os.Exit(1)
	}
}

// usage is the error a command line that names no known command answers.
const usage = "ponsd takes one command, serve, check or version, and is configured by its environment"

// run runs one command. getenv is os.Getenv, out takes what the command
// prints and logs takes the server's log.
func run(ctx context.Context, args []string, getenv func(string) string, out, logs io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("%s", usage)
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintln(out, version.String())
		return err
	case "serve":
		return serve(ctx, getenv, logs, Hooks{})
	case "check":
		return check(ctx, getenv, out, Hooks{})
	}
	return fmt.Errorf("%s; %q is not one", usage, args[0])
}
