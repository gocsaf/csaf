// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/crypto/bcrypt"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/csaf/provider"
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
	defaultCSAFVersion       = csafVersion20
	defaultCSAFPath          = "/.well-known/csaf"
)

// supported CSAF versions
const (
	csafVersion20 = "2.0"
	csafVersion21 = "2.1"
)

type providerMetadataConfig struct {
	ListOnCSAFAggregators   *bool            `toml:"list_on_CSAF_aggregators"`
	MirrorOnCSAFAggregators *bool            `toml:"mirror_on_CSAF_aggregators"`
	MaintainedFrom          *time.Time       `toml:"maintained_from"`
	MaintainedUntil         *time.Time       `toml:"maintained_until"`
	Publisher               *publisherConfig `toml:"publisher"`
}

type publisherConfig struct {
	Category         string             `toml:"category"`
	Name             string             `toml:"name"`
	Namespace        string             `toml:"namespace"`
	Contact          *provider.ContactT `toml:"contact"`
	ContactDetails   *string            `toml:"contact_details"`
	IssuingAuthority *string            `toml:"issuing_authority"`
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
	AuthoritativeVersion    string                       `toml:"authoritative_version"`
	CSAFPath                string                       `toml:"csaf_path"`
	CSAFVersions            []string                     `toml:"csaf_versions"`
	VersionFolders          bool                         `toml:"version_folders"`
}

type tlp string

const (
	tlpCSAF        tlp = "csaf"
	tlpWhite       tlp = "white"
	tlpClear       tlp = "clear"
	tlpGreen       tlp = "green"
	tlpAmber       tlp = "amber"
	tlpAmberStrict tlp = "amber+strict"
	tlpRed         tlp = "red"
)

var allTLPs = []tlp{
	tlpCSAF, tlpWhite, tlpClear, tlpGreen, tlpAmber, tlpAmberStrict, tlpRed,
}

// subsets of TLPs allowed either in CSAF version 2.0 or 2.1
// TODO: do we keep [tlpCSAF] ?
var versionedTLPs = map[string][]tlp{
	csafVersion20: {tlpCSAF, tlpWhite, tlpGreen, tlpAmber, tlpRed},
	csafVersion21: {tlpCSAF, tlpClear, tlpGreen, tlpAmber, tlpAmberStrict, tlpRed},
}

// valid returns true if the checked tlp matches one of the defined tlps.
func (t tlp) valid() bool {
	switch t {
	case tlpCSAF, tlpWhite, tlpClear, tlpGreen, tlpAmber, tlpAmberStrict, tlpRed:
		return true
	default:
		return false
	}
}

// validForVersion returns true if TLP is valid for given CSAF version
func (t tlp) validForVersion(version string) bool {
	return slices.Contains(versionedTLPs[version], t)
}

// label returns TLP label used in documents, i.e.: "amber+strict" -> "AMBER+STRICT"
func (t tlp) label() string {
	return strings.ToUpper(string(t))
}

func feedName(t tlp) string {
	return "csaf-feed-tlp-" + string(t) + ".json"
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

// loadCryptoKeyFromFile loads an armored key from file.
func loadCryptoKeyFromFile(filename string) (*crypto.Key, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
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

	// Check if canonical url prefix is invalid
	parsedURL, err := url.ParseRequestURI(cfg.CanonicalURLPrefix)
	if err != nil {
		return nil, err
	}

	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("invalid canonical URL: %q", cfg.CanonicalURLPrefix)
	}

	if len(cfg.CSAFVersions) == 0 {
		cfg.CSAFVersions = []string{defaultCSAFVersion}
	}

	if cfg.AuthoritativeVersion == "" {
		cfg.AuthoritativeVersion = defaultCSAFVersion
	}

	if cfg.CSAFPath == "" {
		cfg.CSAFPath = defaultCSAFPath
	}

	if cfg.TLPs == nil {
		cfg.TLPs = cfg.defaultTLPs()
	}

	if cfg.ProviderMetaData.Publisher == nil {
		cfg.ProviderMetaData.Publisher = &publisherConfig{
			Category:  string(csaf.CSAFCategoryVendor),
			Name:      "Example Company",
			Namespace: "https://example.com",
		}
	}

	if err := cfg.check(); err != nil {
		return nil, err
	}

	if cfg.UploadLimit == nil {
		ul := int64(defaultUploadLimit)
		cfg.UploadLimit = &ul
	}

	return &cfg, nil
}

// defaultTLPs returns list of TLPs for all configured CSAF versions.
func (cfg *config) defaultTLPs() []tlp {
	var tlps []tlp
	for _, t := range allTLPs {
		if cfg.servesTLP(t) {
			tlps = append(tlps, t)
		}
	}
	return tlps
}

// servesTLP returns true if given TLP is in at least one of the configured CSAF versions.
func (cfg *config) servesTLP(t tlp) bool {
	return slices.ContainsFunc(cfg.CSAFVersions, t.validForVersion)
}

// serves tells if the given CSAF version is configured.
func (cfg *config) serves(version string) bool {
	return slices.Contains(cfg.CSAFVersions, version)
}

// check checks CSAF version specific settings.
func (cfg *config) check() error {
	if len(cfg.CSAFVersions) == 0 {
		return errors.New("csaf_versions needs at least one entry")
	}
	for i, version := range cfg.CSAFVersions {
		if _, ok := versionedTLPs[version]; !ok {
			return fmt.Errorf("Unknown CSAF version %q in csaf_versions", version)
		}
		if slices.Contains(cfg.CSAFVersions[:i], version) {
			return fmt.Errorf("Duplicate CSAF version %q in csaf_versions", version)
		}
	}
	if len(cfg.CSAFVersions) > 1 && !cfg.VersionFolders {
		return errors.New("Need version_folders when serving multiple CSAF versions")
	}
	if !cfg.serves(cfg.AuthoritativeVersion) {
		return fmt.Errorf("authoritative_version %q not in csaf_versions", cfg.AuthoritativeVersion)
	}

	for _, t := range cfg.TLPs {
		if !cfg.servesTLP(t) {
			return fmt.Errorf("tlp %q not available in CSAF %s",
				t, strings.Join(cfg.CSAFVersions, " or "))
		}
	}
	for _, vtr := range cfg.versionTrees() {
		if len(vtr.feedTLPs()) == 0 {
			return fmt.Errorf("no tlp of CSAF %s is configured", vtr.version)
		}
	}

	if p := cfg.CSAFPath; !strings.HasPrefix(p, "/") || p == "/" || path.Clean(p) != p {
		return fmt.Errorf(
			"invalid csaf_path %q: expected an absolute path without trailing slash", p)
	}

	// The version specific PMD values
	pmdc := cfg.ProviderMetaData
	switch {
	case !cfg.serves(csafVersion20) && pmdc.Publisher.ContactDetails != nil:
		return fmt.Errorf("publisher.contact_details needs %q in csaf_versions, use contact", csafVersion20)
	case !cfg.serves(csafVersion21) && pmdc.Publisher.Contact != nil:
		return fmt.Errorf("publisher.contact needs %q in csaf_versions, use contact_details", csafVersion21)
	case !cfg.serves(csafVersion21) && (pmdc.MaintainedFrom != nil || pmdc.MaintainedUntil != nil):
		return fmt.Errorf("maintained_from and maintained_until need %q in csaf_versions", csafVersion21)
	}
	if from, until := pmdc.MaintainedFrom, pmdc.MaintainedUntil; from != nil && until != nil && until.Before(*from) {
		return fmt.Errorf("maintained_until is before maintained_from")
	}
	return nil
}
