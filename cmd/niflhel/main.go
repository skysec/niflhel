package main

import (
	"errors"
	"fmt"
	"niflhel/internal/cli"
	"os"
)

func main() {
	if e := cli.New(os.Stdin, os.Stdout, os.Stderr).Execute(); e != nil {
		var exit cli.ExitError
		if errors.As(e, &exit) {
			os.Exit(exit.Code)
		}
		fmt.Fprintln(os.Stderr, "niflhel:", e)
		os.Exit(125)
	}
}
