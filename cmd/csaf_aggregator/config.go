// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gocsaf/csaf/v5/csaf"
	"github.com/gocsaf/csaf/v5/csaf/aggregator"
	"github.com/gocsaf/csaf/v5/internal/certs"
	"github.com/gocsaf/csaf/v5/internal/filter"
	"github.com/gocsaf/csaf/v5/internal/models"
	"github.com/gocsaf/csaf/v5/internal/options"
	"github.com/gocsaf/csaf/v5/util"
	"golang.org/x/time/rate"
)

const (
	defaultWorkers        = 10
	defaultFolder         = "/var/www"
	defaultWeb            = "/var/www/html"
	defaultDomain         = "https://example.com"
	defaultUpdateInterval = "on best effort"
	defaultLockFile       = "/var/lock/csaf_aggregator/lock"
	defaultAggregatorPath = "/.well-known/csaf-aggregator"
	defaultCSAFVersion    = csafVersion20
)

// supported CSAF versions
const (
	csafVersion20 = "2.0"
	csafVersion21 = "2.1"
)

var csafVersions = []string{csafVersion20, csafVersion21}

type provider struct {
	Name   string `toml:"name"`
	Domain string `toml:"domain"`
	// Rate gives the provider specific rate limiting (see overall Rate).
	Rate         *float64  `toml:"rate"`
	Insecure     *bool     `toml:"insecure"`
	WriteIndices *bool     `toml:"write_indices"`
	Categories   *[]string `toml:"categories"`
	// ServiceDocument incidates if we should create a service.json document.
	ServiceDocument     *bool                                    `toml:"create_service_document"`
	AggregatoryCategory *aggregator.AggregatorAggregatorCategory `toml:"category"`

	// UpdateInterval is as the mandatory `update_interval` if this is a publisher.
	UpdateInterval *string `toml:"update_interval"`

	// IgnorePattern is a list of patterns of advisory URLs to be ignored.
	IgnorePattern []string `toml:"ignore_pattern"`

	// ExtraHeader adds extra HTTP header fields to client
	ExtraHeader http.Header `toml:"header"`

	ClientCert       *string `toml:"client_cert"`
	ClientKey        *string `toml:"client_key"`
	ClientPassphrase *string `toml:"client_passphrase"`

	Range *models.TimeRange `toml:"time_range"`

	clientCerts   []tls.Certificate
	ignorePattern filter.PatternMatcher
	CSAFVersions  []string `toml:"csaf_versions"`
}

type config struct {
	Verbose bool `toml:"verbose"`
	// Workers is the number of concurrently executed workers for downloading.
	Workers int    `toml:"workers"`
	Folder  string `toml:"folder"`
	Web     string `toml:"web"`
	Domain  string `toml:"domain"`
	// Rate gives the average upper limit of https operations per second.
	Rate                 *float64       `toml:"rate"`
	Insecure             *bool          `toml:"insecure"`
	Categories           *[]string      `toml:"categories"`
	WriteIndices         bool           `toml:"write_indices"`
	Aggregator           aggregatorInfo `toml:"aggregator"`
	Providers            []*provider    `toml:"providers"`
	OpenPGPPrivateKey    string         `toml:"openpgp_private_key"`
	OpenPGPPublicKey     string         `toml:"openpgp_public_key"`
	Passphrase           *string        `toml:"passphrase"`
	AllowSingleProvider  bool           `toml:"allow_single_provider"`
	StreamingROLIEParser bool           `long:"streaming_rolie_parser" description:"Use the streaming ROLIE feed parser (experimental)" toml:"streaming_rolie_parser"`

	ClientCert       *string        `toml:"client_cert"`
	ClientKey        *string        `toml:"client_key"`
	ClientPassphrase *string        `toml:"client_passphrase"`
	ClientTimeout    *time.Duration `long:"client_timeout" description:"DURATION for HTTP Client timeouts" value-name:"DURATION" toml:"client_timeout"`

	Range *models.TimeRange `long:"time_range" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"time_range"`

	// LockFile tries to lock to a given file.
	LockFile *string `toml:"lock_file"`

	// Interim performs an interim scan.
	Interim bool `short:"i" long:"interim" description:"Perform an interim scan" toml:"interim"`
	Version bool `long:"version" description:"Display version of the binary" toml:"-"`

	// InterimYears is numbers numbers of years to look back
	// for interim advisories. Less/equal zero means forever.
	InterimYears int `toml:"interim_years"`

	// RemoteValidator configures an optional remote validation.
	RemoteValidatorOptions *csaf.RemoteValidatorOptions `toml:"remote_validator"`

	// ServiceDocument incidates if we should create a service.json document.
	ServiceDocument bool `toml:"create_service_document"`

	// UpdateInterval is used for publishers as the mandatory field
	// 'update_interval'.
	UpdateInterval *string `toml:"update_interval"`

	// IgnorePattern is a list of patterns of advisory URLs to be ignored.
	IgnorePattern []string `toml:"ignore_pattern"`

	// ExtraHeader adds extra HTTP header fields to client
	ExtraHeader http.Header `toml:"header"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	keyMu  sync.Mutex
	key    *crypto.Key
	keyErr error

	clientCerts   []tls.Certificate
	ignorePattern filter.PatternMatcher

	AggregatorPath       string     `toml:"aggregator_path"`
	AuthoritativeVersion string     `toml:"authoritative_version"`
	CSAFVersions         []string   `toml:"csaf_versions"`
	MaintainedFrom       *time.Time `toml:"maintained_from"`
	MaintainedUntil      *time.Time `toml:"maintained_until"`
	VersionFolders       bool       `toml:"version_folders"`
}

// aggregatorInfo is the [aggregator] section of the config.
type aggregatorInfo struct {
	Category         *aggregator.AggregatorAggregatorCategory `toml:"category"`
	Name             string                                   `toml:"name"`
	Namespace        string                                   `toml:"namespace"`
	ContactDetails   *string                                  `toml:"contact_details"`
	IssuingAuthority *string                                  `toml:"issuing_authority"`
}

// validCategory tells if c is a aggregator category.
func validCategory(c aggregator.AggregatorAggregatorCategory) bool {
	return c == aggregator.AggregatorAggregatorCategoryAggregator ||
		c == aggregator.AggregatorAggregatorCategoryLister
}

// check checks the mandatory values of the [aggregator] section.
func (ac *aggregatorInfo) check() error {
	switch {
	case ac.Category == nil:
		return errors.New("aggregator.category is missing")
	case !validCategory(*ac.Category):
		return fmt.Errorf("aggregator.category %q is invalid", *ac.Category)
	case ac.Name == "":
		return errors.New("aggregator.name is missing")
	case ac.Namespace == "":
		return errors.New("aggregator.namespace is missing")
	}
	return nil
}

// configPaths are the potential file locations of the config file.
var configPaths = []string{
	"~/.config/csaf/aggregator.toml",
	"~/.csaf_aggregator.toml",
	"csaf_aggregator.toml",
}

// parseArgsConfig parse the command arguments and loads configuration
// from a configuration file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation: func(cfg *config) string {
			return cfg.Config
		},
		HasVersion: func(cfg *config) bool { return cfg.Version },
		// Establish default values if not set.
		EnsureDefaults: (*config).setDefaults,
	}
	return p.Parse()
}

// tooOldForInterims returns a function that tells if a given
// time is too old for the configured interims interval.
func (c *config) tooOldForInterims() func(time.Time) bool {
	if c.InterimYears <= 0 {
		return func(time.Time) bool { return false }
	}
	from := time.Now().AddDate(-c.InterimYears, 0, 0)
	return func(t time.Time) bool { return t.Before(from) }
}

// ageAccept returns a function which checks if a given time
// is in the accepted download interval of the provider or
// the global config.
func (p *provider) ageAccept(c *config) func(time.Time) bool {
	var r *models.TimeRange
	switch {
	case p.Range != nil:
		r = p.Range
	case c.Range != nil:
		r = c.Range
	default:
		return nil
	}

	if c.Verbose {
		slog.Debug(
			"Setting up filter to accept advisories within time range",
			"from", r[0].Format(time.RFC3339),
			"to", r[1].Format(time.RFC3339),
		)
	}
	return r.Contains
}

// ignoreFile returns true if the given URL should not be downloaded.
func (p *provider) ignoreURL(u string, c *config) bool {
	return p.ignorePattern.Matches(u) || c.ignorePattern.Matches(u)
}

// updateInterval returns the update interval of a publisher.
func (p *provider) updateInterval(c *config) string {
	if p.UpdateInterval != nil {
		return *p.UpdateInterval
	}
	if c.UpdateInterval != nil {
		return *c.UpdateInterval
	}
	return defaultUpdateInterval
}

// serviceDocument tells if we should generate a service document for a
// given provider.
func (p *provider) serviceDocument(c *config) bool {
	if p.ServiceDocument != nil {
		return *p.ServiceDocument
	}
	return c.ServiceDocument
}

// versionConfigured tells if the provider is configured with given CSAF version.
func (p *provider) versionConfigured(version string) bool {
	return p.CSAFVersions == nil || slices.Contains(p.CSAFVersions, version)
}

// writeIndices tells if we should write index.txt and changes.csv.
func (p *provider) writeIndices(c *config) bool {
	if p.WriteIndices != nil {
		return *p.WriteIndices
	}
	return c.WriteIndices
}

func (p *provider) runAsMirror(c *config) bool {
	if p.AggregatoryCategory != nil {
		return *p.AggregatoryCategory == aggregator.AggregatorAggregatorCategoryAggregator
	}
	return c.runAsMirror()
}

// runAsMirror determines if the aggregator should run in mirror mode.
func (c *config) runAsMirror() bool {
	return c.Aggregator.Category != nil &&
		*c.Aggregator.Category == aggregator.AggregatorAggregatorCategoryAggregator
}

func (c *config) privateOpenPGPKey() (*crypto.Key, error) {
	if c.OpenPGPPrivateKey == "" {
		return nil, nil
	}
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.key != nil || c.keyErr != nil {
		return c.key, c.keyErr
	}
	var f *os.File
	if f, c.keyErr = os.Open(c.OpenPGPPrivateKey); c.keyErr != nil {
		return nil, c.keyErr
	}
	defer f.Close()
	c.key, c.keyErr = crypto.NewKeyFromArmoredReader(f)
	return c.key, c.keyErr
}

// httpLog does structured logging in a [util.LoggingClient].
func httpLog(method, url string) {
	slog.Debug("http",
		"method", method,
		"url", url)
}

func (c *config) httpClient(p *provider) util.ClientWithContext {
	hClient := http.Client{}
	if c.ClientTimeout != nil {
		hClient.Timeout = *c.ClientTimeout
	}

	var tlsConfig tls.Config
	if p.Insecure != nil && *p.Insecure || c.Insecure != nil && *c.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	// Use client certs if needed.
	switch {
	// Provider has precedence over global.
	case len(p.clientCerts) != 0:
		tlsConfig.Certificates = p.clientCerts
	case len(c.clientCerts) != 0:
		tlsConfig.Certificates = c.clientCerts
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	client := util.Client(&hClient)

	var cwc util.ClientWithContext

	cwc = &util.BasicClient{Client: client}
	// Add extra headers.
	switch {
	// Provider has precedence over global.
	case len(p.ExtraHeader) > 0:
		cwc = &util.HeaderClient{
			Client: cwc,
			Header: p.ExtraHeader,
		}
	case len(c.ExtraHeader) > 0:
		cwc = &util.HeaderClient{
			Client: cwc,
			Header: c.ExtraHeader,
		}
	default:
		cwc = &util.HeaderClient{
			Client: cwc,
			Header: http.Header{},
		}
	}

	if c.Verbose {
		cwc = &util.LoggingClient{
			Client: cwc,
			Log:    httpLog,
		}
	}

	if p.Rate == nil && c.Rate == nil {
		return cwc
	}

	var r float64
	if c.Rate != nil {
		r = *c.Rate
	}
	if p.Rate != nil {
		r = *p.Rate
	}
	return &util.LimitingClient{
		Client:  cwc,
		Limiter: rate.NewLimiter(rate.Limit(r), 1),
	}
}

// checkAggregatorPath checks that aggregator_path is an absolute
// URL path without trailing slash.
func (c *config) checkAggregatorPath() error {
	if p := c.AggregatorPath; !strings.HasPrefix(p, "/") || p == "/" || path.Clean(p) != p {
		return fmt.Errorf(
			"invalid aggregator_path %q: expected an absolute path without trailing slash", p)
	}
	return nil
}

// checkDomain checks that domain is an absolute URL with no trailing slashes.
func (c *config) checkDomain() error {
	u, err := url.ParseRequestURI(c.Domain)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		strings.HasSuffix(c.Domain, "/") {
		return fmt.Errorf(
			"invalid domain %q: expected an http(s) URL without trailing slash", c.Domain)
	}
	return nil
}

// checkMirror checks provider mirror settings of all configured [versionTree]s.
func (c *config) checkMirror() error {
	for _, vtr := range c.versionTrees() {
		if err := vtr.checkMirror(); err != nil {
			return fmt.Errorf("%s%w", vtr.prefixVer(), err)
		}
	}
	return nil
}

// checkMirror checks provider mirror settings for [versionTree].
func (vtr *versionTree) checkMirror() error {
	c := vtr.cfg
	if c.runAsMirror() {
		if !c.AllowSingleProvider && !vtr.atLeastNMirrors(2) {
			return errors.New("at least 2 providers need to be mirrored")
		} else if c.AllowSingleProvider && !vtr.atLeastNMirrors(1) {
			return errors.New("at least one provider must be mirrored")
		}
	} else if !c.AllowSingleProvider && vtr.atLeastNMirrors(1) {
		return errors.New("found mirrors in a lister aggregator")
	}

	return nil
}

// atLeastNMirrors checks if there are at least n mirrors configured in [versionTree].
func (vtr *versionTree) atLeastNMirrors(n int) bool {
	var mirrors int
	for _, p := range vtr.providers() {
		if p.runAsMirror(vtr.cfg) {
			if mirrors++; mirrors >= n {
				return true
			}
		}
	}
	return false
}

func (c *config) checkProviders() error {
	for _, vtr := range c.versionTrees() {
		if !c.AllowSingleProvider && len(vtr.providers()) < 2 {
			return fmt.Errorf("%sneed at least two providers", vtr.prefixVer())
		}
	}

	already := util.Set[string]{}

	for _, p := range c.Providers {
		if p.Name == "" {
			return errors.New("no name given for provider")
		}
		if p.Domain == "" {
			return errors.New("no domain given for provider")
		}
		if p.AggregatoryCategory != nil && !validCategory(*p.AggregatoryCategory) {
			return fmt.Errorf("invalid category %q for provider %q", *p.AggregatoryCategory, p.Name)
		}
		if already.Contains(p.Name) {
			return fmt.Errorf("provider '%s' is configured more than once", p.Name)
		}
		already.Add(p.Name)
	}
	return nil
}

// checkVersions checks that versions contains supported CSAF versions without
// duplicates.
func checkVersions(key string, versions []string) error {
	if len(versions) == 0 {
		return fmt.Errorf("%s needs at least one configured version", key)
	}
	for i, version := range versions {
		if !slices.Contains(csafVersions, version) {
			return fmt.Errorf("%s: unsupported CSAF version %q", key, version)
		}
		if slices.Contains(versions[:i], version) {
			return fmt.Errorf("%s: duplicate CSAF version %q", key, version)
		}
	}
	return nil
}

// checkVersionSettings checks the CSAF version specific settings.
func (c *config) checkVersionSettings() error {
	if err := checkVersions("csaf_versions", c.CSAFVersions); err != nil {
		return err
	}
	if len(c.CSAFVersions) > 1 && !c.VersionFolders {
		return errors.New("need version_folders when serving multiple CSAF versions")
	}
	if !c.serves(c.AuthoritativeVersion) {
		return fmt.Errorf("csaf_versions missing authoritative_version %q", c.AuthoritativeVersion)
	}
	if !c.serves(csafVersion21) && (c.MaintainedFrom != nil || c.MaintainedUntil != nil) {
		return fmt.Errorf("csaf_versions missing %q for maintained_from and maintaned_until settings", csafVersion21)
	}
	if from, until := c.MaintainedFrom, c.MaintainedUntil; from != nil && until != nil && until.Before(*from) {
		return fmt.Errorf("maintained_until is before maintained_from")
	}
	for _, p := range c.Providers {
		if p.CSAFVersions == nil {
			continue
		}
		key := fmt.Sprintf("csaf_versions of provider %q", p.Name)
		if err := checkVersions(key, p.CSAFVersions); err != nil {
			return err
		}
		for _, version := range p.CSAFVersions {
			if !c.serves(version) {
				return fmt.Errorf("%s: CSAF %s is not in csaf_versions", key, version)
			}
		}
	}
	return nil
}

// serves returns true if CSAF version is configured.
func (c *config) serves(version string) bool {
	return slices.Contains(c.CSAFVersions, version)
}

func (c *config) setDefaults() {
	if c.Folder == "" {
		c.Folder = defaultFolder
	}

	if c.Web == "" {
		c.Web = defaultWeb
	}

	if c.Domain == "" {
		c.Domain = defaultDomain
	}

	if c.AggregatorPath == "" {
		c.AggregatorPath = defaultAggregatorPath
	}

	if len(c.CSAFVersions) == 0 {
		c.CSAFVersions = []string{defaultCSAFVersion}
	}

	if c.AuthoritativeVersion == "" {
		c.AuthoritativeVersion = slices.Min(c.CSAFVersions)
	}

	switch {
	case c.LockFile == nil:
		lockFile := defaultLockFile
		c.LockFile = &lockFile
	case *c.LockFile == "":
		c.LockFile = nil
	}

	if c.Workers <= 0 {
		if n := runtime.NumCPU(); n > defaultWorkers {
			c.Workers = defaultWorkers
		} else {
			c.Workers = n
		}
	}

	// one job per provider and CSAF version.
	if jobs := len(c.Providers) * len(c.CSAFVersions); c.Workers > jobs {
		c.Workers = jobs
	}
}

// prepareLogging sets up the structured logging.
func (c *config) prepareLogging() error {
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewTextHandler(os.Stdout, &ho)
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return nil
}

// compileIgnorePatterns compiles the configured patterns to be ignored.
func (p *provider) compileIgnorePatterns() error {
	pm, err := filter.NewPatternMatcher(p.IgnorePattern)
	if err != nil {
		return fmt.Errorf("invalid ignore patterns for %q: %w", p.Name, err)
	}
	p.ignorePattern = pm
	return nil
}

// compileIgnorePatterns compiles the configured patterns to be ignored.
func (c *config) compileIgnorePatterns() error {
	// Compile the top level patterns.
	pm, err := filter.NewPatternMatcher(c.IgnorePattern)
	if err != nil {
		return err
	}
	c.ignorePattern = pm
	// Compile the patterns of the providers.
	for _, p := range c.Providers {
		if err := p.compileIgnorePatterns(); err != nil {
			return err
		}
	}
	return nil
}

// prepareCertificates loads the provider specific client side certificates
// used by the HTTP client.
func (p *provider) prepareCertificates() error {
	cert, err := certs.LoadCertificate(
		p.ClientCert, p.ClientKey, p.ClientPassphrase)
	if err != nil {
		return fmt.Errorf("invalid certificates for %q: %w", p.Name, err)
	}
	p.clientCerts = cert
	return nil
}

// prepareCertificates loads the client side certificates used by the HTTP client.
func (c *config) prepareCertificates() error {
	// Global certificates
	cert, err := certs.LoadCertificate(
		c.ClientCert, c.ClientKey, c.ClientPassphrase)
	if err != nil {
		return err
	}
	c.clientCerts = cert
	// Provider certificates
	for _, p := range c.Providers {
		if err := p.prepareCertificates(); err != nil {
			return err
		}
	}
	return nil
}

// prepare prepares internal state of a loaded configuration.
func (c *config) prepare() error {
	if len(c.Providers) == 0 {
		return errors.New("no providers given in configuration")
	}

	for _, prepare := range []func() error{
		c.prepareCertificates,
		c.compileIgnorePatterns,
		c.Aggregator.check,
		c.checkDomain,
		c.checkAggregatorPath,
		c.checkVersionSettings,
		c.checkProviders,
		c.checkMirror,
	} {
		if err := prepare(); err != nil {
			return err
		}
	}
	return nil
}
