package main

import (
	"os"
	"regexp"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	if _, err := regexp.Compile(os.Args[1]); err != nil {
		os.Exit(1)
	}
}
