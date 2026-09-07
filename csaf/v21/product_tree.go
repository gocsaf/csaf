// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package v21

// VisitFullProductNames calls visit for all full product names in the product
// tree, including products in nested branches and product paths.
func (pt *CSAFProductTree) VisitFullProductNames(visit func(*FullProductNameT)) {
	if pt == nil || visit == nil {
		return
	}

	for i := range pt.FullProductNames {
		visit(&pt.FullProductNames[i])
	}

	var visitBranches func(BranchesT)
	visitBranches = func(branches BranchesT) {
		for i := range branches {
			branch := &branches[i]
			if branch.Product != nil {
				visit(branch.Product)
			}
			if branch.Branches != nil {
				visitBranches(*branch.Branches)
			}
		}
	}
	visitBranches(pt.Branches)

	// CSAF 2.1 removed relationships
	for i := range pt.ProductPaths {
		visit(&pt.ProductPaths[i].FullProductName)
	}
}

// CollectProductIdentificationHelpers returns all product identification
// helpers for the given product ID.
func (pt *CSAFProductTree) CollectProductIdentificationHelpers(
	id ProductIDT,
) []*FullProductNameTProductIdentificationHelper {
	var helpers []*FullProductNameTProductIdentificationHelper
	pt.FindProductIdentificationHelpers(id, func(helper *FullProductNameTProductIdentificationHelper) {
		helpers = append(helpers, helper)
	})
	return helpers
}

// FindProductIdentificationHelpers calls visit for every product identification
// helper belonging to the given product ID.
func (pt *CSAFProductTree) FindProductIdentificationHelpers(
	id ProductIDT,
	visit func(*FullProductNameTProductIdentificationHelper),
) {
	if visit == nil {
		return
	}
	pt.VisitFullProductNames(func(product *FullProductNameT) {
		if product.ProductID == id && product.ProductIdentificationHelper != nil {
			visit(product.ProductIdentificationHelper)
		}
	})
}
