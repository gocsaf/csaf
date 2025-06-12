// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"reflect"
	"testing"
)

func TestProductTree_FindProductIdentificationHelpers(t *testing.T) {
	type fields struct {
		Branches         Branches
		FullProductNames *FullProductNames
		RelationShips    *Relationships
	}
	type args struct {
		id ProductID
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*ProductIdentificationHelper
	}{
		{
			name: "empty product tree",
			args: args{
				id: "CSAFPID-0001",
			},
			want: nil,
		},
		{
			name: "product tree with matching full product names",
			fields: fields{
				FullProductNames: &FullProductNames{{
					ProductID: &[]ProductID{"CSAFPID-0001"}[0],
					ProductIdentificationHelper: &ProductIdentificationHelper{
						CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
					},
				}},
			},
			args: args{
				id: "CSAFPID-0001",
			},
			want: []*ProductIdentificationHelper{{
				CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
			}},
		},
		{
			name: "product tree with no matching full product names",
			fields: fields{
				FullProductNames: &FullProductNames{{
					ProductID: &[]ProductID{"CSAFPID-0001"}[0],
					ProductIdentificationHelper: &ProductIdentificationHelper{
						CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
					},
				}},
			},
			args: args{
				id: "CSAFPID-0002",
			},
			want: nil,
		},
		{
			name: "product tree with matching branches",
			fields: fields{
				Branches: Branches{{
					Name: &[]string{"beta"}[0],
					Product: &FullProductName{
						ProductID: &[]ProductID{"CSAFPID-0001"}[0],
						ProductIdentificationHelper: &ProductIdentificationHelper{
							CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
						},
					},
					Branches: Branches{{
						Name: &[]string{"beta-2"}[0],
						Product: &FullProductName{
							ProductID: &[]ProductID{"CSAFPID-0001"}[0],
							ProductIdentificationHelper: &ProductIdentificationHelper{
								CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta-2:*:*:*:*:*:*"}[0],
							},
						},
					}},
				}},
			},
			args: args{
				id: "CSAFPID-0001",
			},
			want: []*ProductIdentificationHelper{{
				CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
			}, {
				CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta-2:*:*:*:*:*:*"}[0],
			}},
		},
		{
			name: "product tree with no matching branches",
			fields: fields{
				Branches: Branches{{
					Name: &[]string{"beta"}[0],
					Product: &FullProductName{
						ProductID: &[]ProductID{"CSAFPID-0001"}[0],
						ProductIdentificationHelper: &ProductIdentificationHelper{
							CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
						},
					},
					Branches: Branches{{
						Name: &[]string{"beta-2"}[0],
						Product: &FullProductName{
							ProductID: &[]ProductID{"CSAFPID-0001"}[0],
							ProductIdentificationHelper: &ProductIdentificationHelper{
								CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta-2:*:*:*:*:*:*"}[0],
							},
						},
					}},
				}},
			},
			args: args{
				id: "CSAFPID-0002",
			},
			want: nil,
		},
		{
			name: "product tree with matching relationships",
			fields: fields{
				RelationShips: &Relationships{{
					FullProductName: &FullProductName{
						ProductID: &[]ProductID{"CSAFPID-0001"}[0],
						ProductIdentificationHelper: &ProductIdentificationHelper{
							CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
						},
					},
				}},
			},
			args: args{
				id: "CSAFPID-0001",
			},
			want: []*ProductIdentificationHelper{{
				CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
			}},
		},
		{
			name: "product tree with no matching relationships",
			fields: fields{
				RelationShips: &Relationships{{
					FullProductName: &FullProductName{
						ProductID: &[]ProductID{"CSAFPID-0001"}[0],
						ProductIdentificationHelper: &ProductIdentificationHelper{
							CPE: &[]CPE{"cpe:2.3:a:microsoft:internet_explorer:1.0.0:beta:*:*:*:*:*:*"}[0],
						},
					},
				}},
			},
			args: args{
				id: "CSAFPID-0002",
			},
			want: nil,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			pt := &ProductTree{
				Branches:         test.fields.Branches,
				FullProductNames: test.fields.FullProductNames,
				RelationShips:    test.fields.RelationShips,
			}
			if got := pt.CollectProductIdentificationHelpers(test.args.id); !reflect.DeepEqual(got, test.want) {
				tt.Errorf("ProductTree.FindProductIdentificationHelpers() = %v, want %v",
					got, test.want)
			}
		})
	}
}
