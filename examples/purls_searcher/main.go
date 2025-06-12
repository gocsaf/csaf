// Package main implements a simple demo program to
// work with the csaf library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n  %s [OPTIONS] files...\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	idsString := flag.String("p", "", "ID1,ID2,...")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		log.Println("No files given.")
		return
	}
	if err := run(files, *idsString); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

// run prints PURLs belonging to the given Product IDs.
func run(files []string, ids string) error {
	for _, file := range files {
		adv, err := csaf.LoadAdvisory(file)
		if err != nil {
			return fmt.Errorf("loading %q failed: %w", file, err)
		}

		for _, id := range strings.Split(ids, ",") {
			already := util.Set[csaf.PURL]{}
			i := 0
			adv.ProductTree.FindProductIdentificationHelpers(
				csaf.ProductID(id),
				func(h *csaf.ProductIdentificationHelper) {
					if h.PURL != nil && !already.Contains(*h.PURL) {
						already.Add(*h.PURL)
						i++
						fmt.Printf("%d. %s\n", i, *h.PURL)
					}
				})
		}
	}

	return nil
}
