// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/crypto/bcrypt"

	"github.com/gocsaf/csaf/v3/csaf"
)

const (
	// The environment name, that contains the path to the config file.
	configEnv                = "CSAF_CONFIG"
	configPrefix             = "/etc/csaf"
	defaultConfigPath        = configPrefix + "/config.toml" // Default path to the config file.
	defaultOpenPGPPrivateKey = configPrefix + "/openpgp_private.asc"
	defaultOpenPGPPublicKey  = configPrefix + "/openpgp_public.asc"
	defaultFolder            = "/var/www/"     // Default folder path.
	defaultWeb               = "/var/www/html" // Default web path.
	defaultNoWebUI           = true
	defaultUploadLimit       = 50 * 1024 * 1024 // Default limit size of the uploaded file.
	defaultServiceDocument   = true
)

type providerMetadataConfig struct {
	ListOnCSAFAggregators   *bool           `toml:"list_on_CSAF_aggregators"`
	MirrorOnCSAFAggregators *bool           `toml:"mirror_on_CSAF_aggregators"`
	Publisher               *csaf.Publisher `toml:"publisher"`
}

// configs contains the config values for the provider.
type config struct {
	Password                *string                      `toml:"password"`
	OpenPGPPublicKey        string                       `toml:"openpgp_public_key"`
	OpenPGPPrivateKey       string                       `toml:"openpgp_private_key"`
	Folder                  string                       `toml:"folder"`
	Web                     string                       `toml:"web"`
	TLPs                    []tlp                        `toml:"tlps"`
	UploadSignature         bool                         `toml:"upload_signature"`
	CanonicalURLPrefix      string                       `toml:"canonical_url_prefix"`
	CertificateAndPassword  bool                         `toml:"certificate_and_password"`
	NoPassphrase            bool                         `toml:"no_passphrase"`
	NoValidation            bool                         `toml:"no_validation"`
	NoWebUI                 bool                         `toml:"no_web_ui"`
	DynamicProviderMetaData bool                         `toml:"dynamic_provider_metadata"`
	ProviderMetaData        *providerMetadataConfig      `toml:"provider_metadata"`
	UploadLimit             *int64                       `toml:"upload_limit"`
	Issuer                  *string                      `toml:"issuer"`
	RemoteValidator         *csaf.RemoteValidatorOptions `toml:"remote_validator"`
	Categories              *[]string                    `toml:"categories"`
	ServiceDocument         bool                         `toml:"create_service_document"`
	WriteIndices            bool                         `toml:"write_indices"`
	WriteSecurity           bool                         `toml:"write_security"`
}

func (pmdc *providerMetadataConfig) apply(pmd *csaf.ProviderMetadata) {
	if pmdc == nil {
		return
	}
	if pmdc.ListOnCSAFAggregators != nil {
		pmd.ListOnCSAFAggregators = pmdc.ListOnCSAFAggregators
	}
	if pmdc.MirrorOnCSAFAggregators != nil {
		pmd.MirrorOnCSAFAggregators = pmdc.MirrorOnCSAFAggregators
	}
	if pmdc.Publisher != nil {
		pmd.Publisher = pmdc.Publisher
	}
}

type tlp string

const (
	tlpCSAF  tlp = "csaf"
	tlpWhite tlp = "white"
	tlpGreen tlp = "green"
	tlpAmber tlp = "amber"
	tlpRed   tlp = "red"
)

// valid returns true if the checked tlp matches one of the defined tlps.
func (t tlp) valid() bool {
	switch t {
	case tlpCSAF, tlpWhite, tlpGreen, tlpAmber, tlpRed:
		return true
	default:
		return false
	}
}

func (t *tlp) UnmarshalText(text []byte) error {
	if s := tlp(text); s.valid() {
		*t = s
		return nil
	}
	return fmt.Errorf("invalid config TLP value: %v", string(text))
}

// uploadLimiter returns a reader that reads from a given r reader but stops
// with EOF after the defined bytes in the "UploadLimit" config option.
func (cfg *config) uploadLimiter(r io.Reader) io.Reader {
	// Zero or less means no upload limit.
	if cfg.UploadLimit == nil || *cfg.UploadLimit < 1 {
		return r
	}
	return io.LimitReader(r, *cfg.UploadLimit)
}

func (cfg *config) modelTLPs() []csaf.TLPLabel {
	tlps := make([]csaf.TLPLabel, 0, len(cfg.TLPs))
	for _, t := range cfg.TLPs {
		if t != tlpCSAF {
			tlps = append(tlps, csaf.TLPLabel(strings.ToUpper(string(t))))
		}
	}
	return tlps
}

// loadCryptoKeyFromFile loads an armored key from file.
func loadCryptoKeyFromFile(filename string) (*crypto.Key, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

// openPGPPublicURL constructs the public OpenPGP key URL for a given key.
func (cfg *config) openPGPPublicURL(fingerprint string) string {
	return fmt.Sprintf(
		"%s/.well-known/csaf/openpgp/%s.asc",
		cfg.CanonicalURLPrefix, fingerprint)
}

// checkPassword compares the given hashed password with the plaintext in the "password" config value.
// It returns true if these matches or if the "password" config value is not set, otherwise false.
func (cfg *config) checkPassword(hash string) bool {
	return cfg.Password == nil ||
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(*cfg.Password)) == nil
}

// HasCategories tells if categories are configured.
func (cfg *config) HasCategories() bool {
	return cfg.Categories != nil
}

// categoryExprPrefix is the prefix for dynamic categories.
const categoryExprPrefix = "expr:"

// HasDynamicCategories tells if dynamic categories are configured.
func (cfg *config) HasDynamicCategories() bool {
	if !cfg.HasCategories() {
		return false
	}
	for _, cat := range *cfg.Categories {
		if strings.HasPrefix(cat, categoryExprPrefix) {
			return true
		}
	}
	return false
}

// HasStaticCategories tells if static categories are configured.
func (cfg *config) HasStaticCategories() bool {
	if !cfg.HasCategories() {
		return false
	}
	for _, cat := range *cfg.Categories {
		if !strings.HasPrefix(cat, categoryExprPrefix) {
			return true
		}
	}
	return false
}

// StaticCategories returns a list on the configured static categories.
func (cfg *config) StaticCategories() []string {
	if !cfg.HasCategories() {
		return nil
	}
	cats := make([]string, 0, len(*cfg.Categories))
	for _, cat := range *cfg.Categories {
		if !strings.HasPrefix(cat, categoryExprPrefix) {
			cats = append(cats, cat)
		}
	}
	return cats
}

// DynamicCategories returns a list on the configured dynamic categories.
func (cfg *config) DynamicCategories() []string {
	if !cfg.HasCategories() {
		return nil
	}
	cats := make([]string, 0, len(*cfg.Categories))
	for _, cat := range *cfg.Categories {
		if strings.HasPrefix(cat, categoryExprPrefix) {
			cats = append(cats, cat[len(categoryExprPrefix):])
		}
	}
	return cats
}

// loadConfig extracts the config values from the config file. The path to the
// file is taken either from environment variable "CSAF_CONFIG" or from the
// defined default path in "defaultConfigPath".
// Default values are set in case some are missing in the file.
// It returns these values in a struct and nil if there is no error.
func loadConfig() (*config, error) {
	path := os.Getenv(configEnv)
	if path == "" {
		path = defaultConfigPath
	}

	// Preset defaults
	cfg := config{
		NoWebUI:         defaultNoWebUI,
		ServiceDocument: defaultServiceDocument,
	}

	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, err
	}

	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("could not parse %q from config.toml", undecoded)
	}

	// Preset defaults

	if cfg.OpenPGPPrivateKey == "" {
		cfg.OpenPGPPrivateKey = defaultOpenPGPPrivateKey
	}

	if cfg.OpenPGPPublicKey == "" {
		cfg.OpenPGPPublicKey = defaultOpenPGPPublicKey
	}

	if cfg.Folder == "" {
		cfg.Folder = defaultFolder
	}

	if cfg.Web == "" {
		cfg.Web = defaultWeb
	}

	if cfg.CanonicalURLPrefix == "" {
		cfg.CanonicalURLPrefix = "https://" + os.Getenv("SERVER_NAME")
	}

	if cfg.TLPs == nil {
		cfg.TLPs = []tlp{tlpCSAF, tlpWhite, tlpGreen, tlpAmber, tlpRed}
	}

	if cfg.ProviderMetaData == nil {
		cfg.ProviderMetaData = &providerMetadataConfig{}
	}

	if cfg.ProviderMetaData.Publisher == nil {
		cfg.ProviderMetaData.Publisher = &csaf.Publisher{
			Category:  func(c csaf.Category) *csaf.Category { return &c }(csaf.CSAFCategoryVendor),
			Name:      func(s string) *string { return &s }("Example Company"),
			Namespace: func(s string) *string { return &s }("https://example.com"),
		}
	}

	if cfg.UploadLimit == nil {
		ul := int64(defaultUploadLimit)
		cfg.UploadLimit = &ul
	}

	return &cfg, nil
}
