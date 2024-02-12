package main

import (
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

func init() {
	// Seed random number generator
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// Change working directory to the directory of the executable
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	os.Chdir(dir)
}
