// Package main implements a simple demo program to
// work with the csaf library.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gocsaf/csaf/v3/csaf"
	"log"
	"os"
)

func main() {
	flag.Usage = func() {
		if _, err := fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n  %s [OPTIONS] files...\n\nOptions:\n", os.Args[0]); err != nil {
			log.Fatalf("error: %v\n", err)
		}
		flag.PrintDefaults()
	}
	printProductIdentHelper := flag.Bool("print_ident_helper", false, "print product helper mapping")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		log.Println("No files given.")
		return
	}
	if err := run(files, *printProductIdentHelper); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

// visitFullProductNames iterates all full product names in the advisory.
func visitFullProductNames(
	adv *csaf.Advisory,
	visit func(*csaf.FullProductName),
) {
	// Iterate over all full product names
	if fpns := adv.ProductTree.FullProductNames; fpns != nil {
		for _, fpn := range *fpns {
			if fpn != nil && fpn.ProductID != nil {
				visit(fpn)
			}
		}
	}

	// Iterate over branches recursively
	var recBranch func(b *csaf.Branch)
	recBranch = func(b *csaf.Branch) {
		if b == nil {
			return
		}
		if fpn := b.Product; fpn != nil && fpn.ProductID != nil {
			visit(fpn)

		}
		for _, c := range b.Branches {
			recBranch(c)
		}
	}
	for _, b := range adv.ProductTree.Branches {
		recBranch(b)
	}

	// Iterate over relationships
	if rels := adv.ProductTree.RelationShips; rels != nil {
		for _, rel := range *rels {
			if rel != nil {
				if fpn := rel.FullProductName; fpn != nil && fpn.ProductID != nil {
					visit(fpn)
				}
			}
		}
	}
}

// run prints all product IDs and their full_product_names and product_identification_helpers.
func run(files []string, printProductIdentHelper bool) error {
	for _, file := range files {
		adv, err := csaf.LoadAdvisory(file)
		if err != nil {
			return fmt.Errorf("loading %q failed: %w", file, err)
		}
		if printProductIdentHelper {
			printProductIdentHelperMapping(adv)
		} else {
			printProductIDMapping(adv)
		}
	}

	return nil
}

// printProductIDMapping prints all product ids with their name and identification helper.
func printProductIDMapping(adv *csaf.Advisory) {
	type productNameHelperMapping struct {
		FullProductName             *csaf.FullProductName
		ProductIdentificationHelper *csaf.ProductIdentificationHelper
	}

	productIDMap := map[csaf.ProductID][]productNameHelperMapping{}

	visitFullProductNames(adv, func(fpn *csaf.FullProductName) {
		productIDMap[*fpn.ProductID] = append(productIDMap[*fpn.ProductID], productNameHelperMapping{
			FullProductName:             fpn,
			ProductIdentificationHelper: fpn.ProductIdentificationHelper,
		})
	})

	jsonData, _ := json.MarshalIndent(productIDMap, "", "  ")
	fmt.Println(string(jsonData))
}

// printProductIdentHelperMapping prints all product identifier helper with their product id.
func printProductIdentHelperMapping(adv *csaf.Advisory) {
	type productIdentIDMapping struct {
		ProductNameHelperMapping csaf.ProductIdentificationHelper
		ProductID                *csaf.ProductID
	}

	productIdentMap := []productIdentIDMapping{}
	visitFullProductNames(adv, func(fpn *csaf.FullProductName) {
		productIdentMap = append(productIdentMap, productIdentIDMapping{
			ProductNameHelperMapping: *fpn.ProductIdentificationHelper,
			ProductID:                fpn.ProductID,
		})
	})
	jsonData, _ := json.MarshalIndent(productIdentMap, "", "  ")
	fmt.Println(string(jsonData))
}
