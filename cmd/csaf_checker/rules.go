// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"sort"

	"github.com/gocsaf/csaf/v3/csaf"
)

type ruleCondition int

const (
	condAll ruleCondition = iota
	condOneOf
)

type requirementRules struct {
	cond      ruleCondition
	satisfies int
	subs      []*requirementRules
}

var (
	publisherRules = &requirementRules{
		cond: condAll,
		subs: ruleAtoms(1, 2, 3, 4),
	}

	providerRules = &requirementRules{
		cond: condAll,
		subs: []*requirementRules{
			publisherRules,
			{cond: condAll, subs: ruleAtoms(5, 6, 7)},
			{cond: condOneOf, subs: ruleAtoms(8, 9, 10)},
			{cond: condOneOf, subs: []*requirementRules{
				{cond: condAll, subs: ruleAtoms(11, 12, 13, 14)},
				{cond: condAll, subs: ruleAtoms(15, 16, 17)},
			}},
		},
	}

	trustedProviderRules = &requirementRules{
		cond: condAll,
		subs: []*requirementRules{
			providerRules,
			{cond: condAll, subs: ruleAtoms(18, 19, 20)},
		},
	}
)

// roleRequirements returns the rules for the given role.
func roleRequirements(role csaf.MetadataRole) *requirementRules {
	switch role {
	case csaf.MetadataRoleTrustedProvider:
		return trustedProviderRules
	case csaf.MetadataRoleProvider:
		return providerRules
	case csaf.MetadataRolePublisher:
		return publisherRules
	default:
		return nil
	}
}

// ruleAtoms is a helper function to build the leaves of
// a rules tree.
func ruleAtoms(nums ...int) []*requirementRules {
	rules := make([]*requirementRules, len(nums))
	for i, num := range nums {
		rules[i] = &requirementRules{
			cond:      condAll,
			satisfies: num,
		}
	}
	return rules
}

// reporters assembles a list of reporters needed for a given set
// of rules. The given nums are mandatory.
func (rules *requirementRules) reporters(nums []int) []reporter {
	if rules == nil {
		return nil
	}

	var recurse func(*requirementRules)
	recurse = func(rules *requirementRules) {
		if rules.satisfies != 0 {
			// There should not be any dupes.
			for _, n := range nums {
				if n == rules.satisfies {
					goto doRecurse
				}
			}
			nums = append(nums, rules.satisfies)
		}
	doRecurse:
		for _, sub := range rules.subs {
			recurse(sub)
		}
	}
	recurse(rules)

	sort.Ints(nums)

	reps := make([]reporter, len(nums))

	for i, n := range nums {
		reps[i] = reporters[n]
	}
	return reps
}

// eval evalutes a set of rules given a given processor state.
func (rules *requirementRules) eval(p *processor) bool {
	if rules == nil {
		return false
	}

	var recurse func(*requirementRules) bool

	recurse = func(rules *requirementRules) bool {
		if rules.satisfies != 0 {
			return p.eval(rules.satisfies)
		}
		switch rules.cond {
		case condAll:
			for _, sub := range rules.subs {
				if !recurse(sub) {
					return false
				}
			}
			return true
		case condOneOf:
			for _, sub := range rules.subs {
				if recurse(sub) {
					return true
				}
			}
			return false
		default:
			panic(fmt.Sprintf("unexpected cond %v in eval", rules.cond))
		}
	}

	return recurse(rules)
}

// eval evalutes the processing state for a given requirement.
func (p *processor) eval(requirement int) bool {

	switch requirement {
	case 1:
		return !p.invalidAdvisories.hasErrors()
	case 2:
		return !p.badFilenames.hasErrors()
	case 3:
		return len(p.noneTLS) == 0
	case 4:
		return !p.badWhitePermissions.hasErrors()
	case 5:
		return !p.badAmberRedPermissions.hasErrors()
	// Currently, only domains using HTTP-Header redirects are checked.
	// A domain reaching evaluation will only have HTTP-Header redirects if any,
	// and thus requirement 6 will always be fullfilled.
	case 6:
		return true
	case 7:
		return !p.badProviderMetadata.hasErrors()
	case 8:
		return !p.badSecurity.hasErrors()
	case 9:
		return !p.badWellknownMetadata.hasErrors()
	case 10:
		return !p.badDNSPath.hasErrors()

	case 11:
		return !p.badFolders.hasErrors()
	case 12:
		return !p.badIndices.hasErrors()
	case 13:
		return !p.badChanges.hasErrors()
	case 14:
		return !p.badDirListings.hasErrors()

	case 15:
		return !p.badROLIEFeed.hasErrors()
	case 16:
		return !p.badROLIEService.hasErrors()
	case 17:
		return !p.badROLIECategory.hasErrors()

	case 18:
		return !p.badIntegrities.hasErrors()
	case 19:
		return !p.badSignatures.hasErrors()
	case 20:
		return !p.badPGPs.hasErrors()
	default:
		panic(fmt.Sprintf("evaluating unexpected requirement %d", requirement))
	}
}
