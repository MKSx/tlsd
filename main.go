package main

import (
	"github.com/MKSx/tlsd/cmd"
)

func main() {

	if err := cmd.GetCommand().Execute(); err != nil {
		panic(err)
	}
}
