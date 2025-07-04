package csaf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAdvisory(t *testing.T) {
	type args struct {
		jsonDir string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{{
		name:    "Valid documents",
		args:    args{jsonDir: "csaf-documents/valid"},
		wantErr: false,
	},
		{
			name:    "Unknown fields",
			args:    args{jsonDir: "csaf-documents/unknown-fields"},
			wantErr: true,
		},
		{
			name:    "Garbage trailing data",
			args:    args{jsonDir: "csaf-documents/trailing-garbage-data"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := filepath.Walk("../testdata/"+tt.args.jsonDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.Mode().IsRegular() && filepath.Ext(info.Name()) == ".json" {
					if _, err := LoadAdvisory(path); (err != nil) != tt.wantErr {
						t.Errorf("LoadAdvisory() error = %v, wantErr %v", err, tt.wantErr)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
