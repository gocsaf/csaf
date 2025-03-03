// Package main implements a simple demo program to
// work with the csaf library.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gocsaf/csaf/v3/csaf"
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

	var printer func(*csaf.Advisory) error
	if *printProductIdentHelper {
		printer = printProductIdentHelperMapping
	} else {
		printer = printProductIDMapping
	}

	if err := run(files, printer); err != nil {
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

// run applies fn to all loaded advisories.
func run(files []string, fn func(*csaf.Advisory) error) error {
	for _, file := range files {
		adv, err := csaf.LoadAdvisory(file)
		if err != nil {
			return fmt.Errorf("loading %q failed: %w", file, err)
		}
		if err := fn(adv); err != nil {
			return err
		}
	}
	return nil
}

// printJSON serializes v as indented JSON to stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printProductIDMapping prints all product ids with their name and identification helper.
func printProductIDMapping(adv *csaf.Advisory) error {
	type productNameHelperMapping struct {
		FullProductName             *csaf.FullProductName             `json:"product"`
		ProductIdentificationHelper *csaf.ProductIdentificationHelper `json:"product_identification_helper"`
	}

	productIDMap := map[csaf.ProductID][]productNameHelperMapping{}
	visitFullProductNames(adv, func(fpn *csaf.FullProductName) {
		productIDMap[*fpn.ProductID] = append(productIDMap[*fpn.ProductID], productNameHelperMapping{
			FullProductName:             fpn,
			ProductIdentificationHelper: fpn.ProductIdentificationHelper,
		})
	})
	return printJSON(productIDMap)
}

// printProductIdentHelperMapping prints all product identifier helper with their product id.
func printProductIdentHelperMapping(adv *csaf.Advisory) error {
	type productIdentIDMapping struct {
		ProductNameHelperMapping csaf.ProductIdentificationHelper `json:"product_identification_helper"`
		ProductID                *csaf.ProductID                  `json:"product_id"`
	}

	productIdentMap := []productIdentIDMapping{}
	visitFullProductNames(adv, func(fpn *csaf.FullProductName) {
		productIdentMap = append(productIdentMap, productIdentIDMapping{
			ProductNameHelperMapping: *fpn.ProductIdentificationHelper,
			ProductID:                fpn.ProductID,
		})
	})
	return printJSON(productIdentMap)
}
