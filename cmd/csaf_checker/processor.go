// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gocsaf/csaf/v3/internal/misc"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/time/rate"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// topicMessages stores the collected topicMessages for a specific topic.
type topicMessages []Message

type processor struct {
	cfg          *config
	validator    csaf.RemoteValidator
	client       util.Client
	unauthClient util.Client

	redirects      map[string][]string
	noneTLS        util.Set[string]
	alreadyChecked map[string]whereType
	pmdURL         string
	pmd256         []byte
	pmd            any
	keys           *crypto.KeyRing
	labelChecker   labelChecker
	timesChanges   map[string]time.Time
	timesAdv       map[string]time.Time

	invalidAdvisories      topicMessages
	badFilenames           topicMessages
	badIntegrities         topicMessages
	badPGPs                topicMessages
	badSignatures          topicMessages
	badProviderMetadata    topicMessages
	badSecurity            topicMessages
	badIndices             topicMessages
	badChanges             topicMessages
	badFolders             topicMessages
	badWellknownMetadata   topicMessages
	badDNSPath             topicMessages
	badDirListings         topicMessages
	badROLIEFeed           topicMessages
	badROLIEService        topicMessages
	badROLIECategory       topicMessages
	badWhitePermissions    topicMessages
	badAmberRedPermissions topicMessages

	expr *util.PathEval
}

// reporter is implemented by any value that has a report method.
// The implementation of the report controls how to test
// the respective requirement and generate the report.
type reporter interface {
	report(*processor, *Domain)
}

// errContinue indicates that the current check should continue.
var errContinue = errors.New("continue")

type whereType byte

const (
	rolieMask = whereType(1) << iota
	indexMask
	changesMask
	listingMask
)

func (wt whereType) String() string {
	switch wt {
	case rolieMask:
		return "ROLIE"
	case indexMask:
		return "index.txt"
	case changesMask:
		return "changes.csv"
	case listingMask:
		return "directory listing"
	default:
		var mixed []string
		for mask := rolieMask; mask <= changesMask; mask <<= 1 {
			if x := wt & mask; x == mask {
				mixed = append(mixed, x.String())
			}
		}
		return strings.Join(mixed, "|")
	}
}

// add adds a message to this topic.
func (m *topicMessages) add(typ MessageType, format string, args ...any) {
	*m = append(*m, Message{Type: typ, Text: fmt.Sprintf(format, args...)})
}

// error adds an error message to this topic.
func (m *topicMessages) error(format string, args ...any) {
	m.add(ErrorType, format, args...)
}

// warn adds a warning message to this topic.
func (m *topicMessages) warn(format string, args ...any) {
	m.add(WarnType, format, args...)
}

// info adds an info message to this topic.
func (m *topicMessages) info(format string, args ...any) {
	m.add(InfoType, format, args...)
}

// use signals that we're going to use this topic.
func (m *topicMessages) use() {
	if *m == nil {
		*m = []Message{}
	}
}

// reset resets the messages to this topic.
func (m *topicMessages) reset() { *m = nil }

// used returns true if we have used this topic.
func (m *topicMessages) used() bool { return *m != nil }

// hasErrors checks if there are any error messages.
func (m *topicMessages) hasErrors() bool {
	if !m.used() {
		return false
	}
	for _, msg := range *m {
		if msg.Type == ErrorType {
			return true
		}
	}
	return false
}

// newProcessor returns an initialized processor.
func newProcessor(cfg *config) (*processor, error) {
	var validator csaf.RemoteValidator

	if cfg.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     cfg.RemoteValidator,
			Presets: cfg.RemoteValidatorPresets,
			Cache:   cfg.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return nil, fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
	}

	return &processor{
		cfg:            cfg,
		alreadyChecked: map[string]whereType{},
		expr:           util.NewPathEval(),
		validator:      validator,
		labelChecker: labelChecker{
			advisories:      map[csaf.TLPLabel]util.Set[string]{},
			whiteAdvisories: map[identifier]bool{},
		},
		timesAdv:     map[string]time.Time{},
		timesChanges: map[string]time.Time{},
		noneTLS:      util.Set[string]{},
	}, nil
}

// close closes external ressources of the processor.
func (p *processor) close() {
	if p.validator != nil {
		p.validator.Close()
		p.validator = nil
	}
}

// reset clears the fields values of the given processor.
func (p *processor) reset() {
	p.redirects = nil
	p.pmdURL = ""
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil
	clear(p.alreadyChecked)
	clear(p.noneTLS)
	clear(p.timesAdv)
	clear(p.timesChanges)

	p.invalidAdvisories.reset()
	p.badFilenames.reset()
	p.badIntegrities.reset()
	p.badPGPs.reset()
	p.badSignatures.reset()
	p.badProviderMetadata.reset()
	p.badSecurity.reset()
	p.badIndices.reset()
	p.badChanges.reset()
	p.badFolders.reset()
	p.badWellknownMetadata.reset()
	p.badDNSPath.reset()
	p.badDirListings.reset()
	p.badROLIEFeed.reset()
	p.badROLIEService.reset()
	p.badROLIECategory.reset()
	p.badWhitePermissions.reset()
	p.badAmberRedPermissions.reset()
	p.labelChecker.reset()
}

// run calls checkDomain function for each domain in the given "domains" parameter.
// Then it calls the report method on each report from the given "reporters" parameter for each domain.
// It returns a pointer to the report and nil, otherwise an error.
func (p *processor) run(domains []string) (*Report, error) {
	report := Report{
		Date:      ReportTime{Time: time.Now().UTC()},
		Version:   util.SemVersion,
		TimeRange: p.cfg.Range,
	}

	for _, d := range domains {
		p.reset()

		if !p.checkProviderMetadata(d) {
			// We cannot build a report if the provider metadata cannot be parsed.
			log.Printf("Could not parse the Provider-Metadata.json of: %s\n", d)
			continue
		}
		if err := p.checkDomain(d); err != nil {
			log.Printf("Failed to find valid provider-metadata.json for domain %s: %v. "+
				"Continuing with next domain.", d, err)
			continue
		}
		domain := &Domain{Name: d}

		if err := p.fillMeta(domain); err != nil {
			log.Printf("Filling meta data failed: %v\n", err)
			// reporters depend on role.
			continue
		}

		if domain.Role == nil {
			log.Printf("No role found in meta data. Ignoring domain %q\n", d)
			continue
		}

		rules := roleRequirements(*domain.Role)
		// TODO: store error base on rules eval in report.
		if rules == nil {
			log.Printf(
				"WARN: Cannot find requirement rules for role %q. Assuming trusted provider.\n",
				*domain.Role)
			rules = trustedProviderRules
		}

		// 18, 19, 20 should always be checked.
		for _, r := range rules.reporters([]int{18, 19, 20}) {
			r.report(p, domain)
		}

		domain.Passed = rules.eval(p)

		report.Domains = append(report.Domains, domain)
	}

	return &report, nil
}

// fillMeta fills the report with extra informations from provider metadata.
func (p *processor) fillMeta(domain *Domain) error {
	if p.pmd == nil {
		return nil
	}

	var (
		pub  csaf.Publisher
		role csaf.MetadataRole
	)

	if err := p.expr.Match([]util.PathEvalMatcher{
		{Expr: `$.publisher`, Action: util.ReMarshalMatcher(&pub), Optional: true},
		{Expr: `$.role`, Action: util.ReMarshalMatcher(&role), Optional: true},
	}, p.pmd); err != nil {
		return err
	}

	domain.Publisher = &pub
	domain.Role = &role

	return nil
}

// domainChecks compiles a list of checks which should be performed
// for a given domain.
func (p *processor) domainChecks(domain string) []func(*processor, string) error {
	// If we have a direct domain url we dont need to
	// perform certain checks.
	direct := strings.HasPrefix(domain, "https://")

	checks := []func(*processor, string) error{
		(*processor).checkPGPKeys,
	}

	if !direct {
		checks = append(checks, (*processor).checkWellknownSecurityDNS)
	} else {
		p.badSecurity.use()
		p.badSecurity.info(
			"Performed no test of security.txt " +
				"since the direct url of the provider-metadata.json was used.")
		p.badWellknownMetadata.use()
		p.badWellknownMetadata.info(
			"Performed no test on whether the provider-metadata.json is available " +
				"under the .well-known path " +
				"since the direct url of the provider-metadata.json was used.")
		p.badDNSPath.use()
		p.badDNSPath.info(
			"Performed no test on the contents of https://csaf.data.security.DOMAIN " +
				"since the direct url of the provider-metadata.json was used.")
	}

	checks = append(checks,
		(*processor).checkCSAFs,
		(*processor).checkMissing,
		(*processor).checkInvalid,
		(*processor).checkListing,
		(*processor).checkWhitePermissions,
	)

	return checks
}

// checkDomain runs a set of domain specific checks on a given
// domain.
func (p *processor) checkDomain(domain string) error {
	for _, check := range p.domainChecks(domain) {
		if err := check(p, domain); err != nil {
			if err == errContinue {
				continue
			}
			return err
		}
	}
	return nil
}

// checkTLS parses the given URL to check its schema, as a result it sets
// the value of "noneTLS" field if it is not HTTPS.
func (p *processor) checkTLS(u string) {
	if x, err := url.Parse(u); err == nil && x.Scheme != "https" {
		p.noneTLS.Add(u)
	}
}

func (p *processor) markChecked(s string, mask whereType) bool {
	v, ok := p.alreadyChecked[s]
	p.alreadyChecked[s] = v | mask
	return ok
}

func (p *processor) checkRedirect(r *http.Request, via []*http.Request) error {
	url := r.URL.String()
	p.checkTLS(url)
	if p.redirects == nil {
		p.redirects = map[string][]string{}
	}

	if redirects := p.redirects[url]; len(redirects) == 0 {
		redirects = make([]string, len(via))
		for i, v := range via {
			redirects[i] = v.URL.String()
		}
		p.redirects[url] = redirects
	}

	if len(via) > 10 {
		return errors.New("too many redirections")
	}
	return nil
}

// fullClient returns a fully configure HTTP client.
func (p *processor) fullClient() util.Client {
	hClient := http.Client{}

	hClient.CheckRedirect = p.checkRedirect

	var tlsConfig tls.Config
	if p.cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(p.cfg.clientCerts) != 0 {
		tlsConfig.Certificates = p.cfg.clientCerts
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	client := util.Client(&hClient)

	// Add extra headers.
	client = &util.HeaderClient{
		Client: client,
		Header: p.cfg.ExtraHeader,
	}

	// Add optional URL logging.
	if p.cfg.Verbose {
		client = &util.LoggingClient{Client: client}
	}

	// Add optional rate limiting.
	if p.cfg.Rate != nil {
		client = &util.LimitingClient{
			Client:  client,
			Limiter: rate.NewLimiter(rate.Limit(*p.cfg.Rate), 1),
		}
	}
	return client
}

// basicClient returns a http Client w/o certs and headers.
func (p *processor) basicClient() *http.Client {
	if p.cfg.Insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		}
		return &http.Client{Transport: tr}
	}
	return &http.Client{}
}

// httpClient returns a cached HTTP client to be used to
// download remote ressources.
func (p *processor) httpClient() util.Client {
	if p.client == nil {
		p.client = p.fullClient()
	}
	return p.client
}

// unauthorizedClient returns a cached HTTP client without
// authentification.
func (p *processor) unauthorizedClient() util.Client {
	if p.unauthClient == nil {
		p.unauthClient = p.basicClient()
	}
	return p.unauthClient
}

// usedAuthorizedClient tells if an authorized client is used
// for downloading.
func (p *processor) usedAuthorizedClient() bool {
	return p.cfg.protectedAccess()
}

// rolieFeedEntries loads the references to the advisory files for a given feed.
func (p *processor) rolieFeedEntries(feed string) ([]csaf.AdvisoryFile, error) {
	client := p.httpClient()
	res, err := client.Get(feed)
	p.badDirListings.use()
	if err != nil {
		p.badProviderMetadata.error("Cannot fetch feed %s: %v", feed, err)
		return nil, errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badProviderMetadata.warn("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return nil, errContinue
	}

	rfeed, rolieDoc, err := func() (*csaf.ROLIEFeed, any, error) {
		defer res.Body.Close()
		all, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, nil, err
		}
		rfeed, err := csaf.LoadROLIEFeed(bytes.NewReader(all))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", feed, err)
		}
		var rolieDoc any
		err = json.NewDecoder(bytes.NewReader(all)).Decode(&rolieDoc)
		return rfeed, rolieDoc, err
	}()
	if err != nil {
		p.badProviderMetadata.error("Loading ROLIE feed failed: %v.", err)
		return nil, errContinue
	}

	if rfeed.CountEntries() == 0 {
		p.badROLIEFeed.warn("No entries in %s", feed)
	}
	errors, err := csaf.ValidateROLIE(rolieDoc)
	if err != nil {
		return nil, err
	}
	if len(errors) > 0 {
		p.badProviderMetadata.error("%s: Validating against JSON schema failed:", feed)
		for _, msg := range errors {
			p.badProviderMetadata.error(strings.ReplaceAll(msg, `%`, `%%`))
		}
	}

	// Extract the CSAF files from feed.
	var files []csaf.AdvisoryFile

	rfeed.Entries(func(entry *csaf.Entry) {
		// Filter if we have date checking.
		if accept := p.cfg.Range; accept != nil {
			if t := time.Time(entry.Updated); !t.IsZero() && !accept.Contains(t) {
				return
			}
		}

		var url, sha256, sha512, sign string
		for i := range entry.Link {
			link := &entry.Link[i]
			lower := strings.ToLower(link.HRef)
			switch link.Rel {
			case "self":
				if !strings.HasSuffix(lower, ".json") {
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "self" has unexpected file extension.`,
						link.HRef, feed)
				}
				url = link.HRef
			case "signature":
				if !strings.HasSuffix(lower, ".asc") {
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "signature" has unexpected file extension.`,
						link.HRef, feed)
				}
				sign = link.HRef
			case "hash":
				switch {
				case strings.HasSuffix(lower, "sha256"):
					sha256 = link.HRef
				case strings.HasSuffix(lower, "sha512"):
					sha512 = link.HRef
				default:
					p.badProviderMetadata.warn(
						`ROLIE feed entry link %s in %s with "rel": "hash" has unsupported file extension.`,
						link.HRef, feed)
				}
			}
		}

		if url == "" {
			p.badProviderMetadata.warn(
				`ROLIE feed %s contains entry link with no "self" URL.`, feed)
			return
		}

		var file csaf.AdvisoryFile

		switch {
		case sha256 == "" && sha512 != "":
			p.badROLIEFeed.info("%s has no sha256 hash file listed", url)
		case sha256 != "" && sha512 == "":
			p.badROLIEFeed.info("%s has no sha512 hash file listed", url)
		case sha256 == "" && sha512 == "":
			p.badROLIEFeed.error("No hash listed on ROLIE feed %s", url)
		case sign == "":
			p.badROLIEFeed.error("No signature listed on ROLIE feed %s", url)
		}
		file = csaf.PlainAdvisoryFile{Path: url, SHA256: sha256, SHA512: sha512, Sign: sign}

		files = append(files, file)
	})

	return files, nil
}

// makeAbsolute returns a function that checks if a given
// URL is absolute or not. If not it returns an
// absolute URL based on a given base URL.
func makeAbsolute(base *url.URL) func(*url.URL) *url.URL {
	return func(u *url.URL) *url.URL {
		if u.IsAbs() {
			return u
		}
		return base.JoinPath(u.String())
	}
}

var yearFromURL = regexp.MustCompile(`.*/(\d{4})/[^/]+$`)

// integrity checks several csaf.AdvisoryFiles for formal
// mistakes, from conforming filenames to invalid advisories.
func (p *processor) integrity(
	files []csaf.AdvisoryFile,
	base string,
	mask whereType,
	lg func(MessageType, string, ...any),
) error {
	b, err := url.Parse(base)
	if err != nil {
		return err
	}
	client := p.httpClient()

	var data bytes.Buffer

	for _, f := range files {
		fp, err := url.Parse(f.URL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f, err)
			continue
		}

		u := misc.JoinURL(b, fp).String()

		// Should this URL be ignored?
		if p.cfg.ignoreURL(u) {
			if p.cfg.Verbose {
				log.Printf("Ignoring %q\n", u)
			}
			continue
		}

		if p.markChecked(u, mask) {
			continue
		}
		p.checkTLS(u)

		// Check if the filename is conforming.
		p.badFilenames.use()
		if !util.ConformingFileName(filepath.Base(u)) {
			p.badFilenames.error("%s does not have a conforming filename.", u)
		}

		var folderYear *int
		if m := yearFromURL.FindStringSubmatch(u); m != nil {
			year, _ := strconv.Atoi(m[1])
			folderYear = &year
		}

		res, err := client.Get(u)
		if err != nil {
			lg(ErrorType, "Fetching %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			lg(ErrorType, "Fetching %s failed: Status code %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		// Error if we do not get JSON.
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			lg(ErrorType,
				"The content type of %s should be 'application/json' but is '%s'",
				u, ct)
		}

		s256 := sha256.New()
		s512 := sha512.New()
		data.Reset()
		hasher := io.MultiWriter(s256, s512, &data)

		var doc any

		if err := func() error {
			defer res.Body.Close()
			tee := io.TeeReader(res.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			lg(ErrorType, "Reading %s failed: %v", u, err)
			continue
		}

		p.invalidAdvisories.use()

		// Validate against JSON schema.
		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			p.invalidAdvisories.error("Failed to validate %s: %v", u, err)
			continue
		}
		if len(errors) > 0 {
			p.invalidAdvisories.error("CSAF file %s has %d validation errors.", u, len(errors))
		}

		if err := util.IDMatchesFilename(p.expr, doc, filepath.Base(u)); err != nil {
			p.badFilenames.error("%s: %v", u, err)
			continue

		}
		// Validate against remote validator.
		if p.validator != nil {
			if rvr, err := p.validator.Validate(doc); err != nil {
				p.invalidAdvisories.error("Calling remote validator on %s failed: %v", u, err)
			} else if !rvr.Valid {
				p.invalidAdvisories.error("Remote validation of %s failed.", u)
			}
		}

		p.labelChecker.check(p, doc, u)

		// Check if file is in the right folder.
		p.badFolders.use()

		switch date, fault := p.extractTime(doc, `initial_release_date`, u); {
		case fault != "":
			p.badFolders.error(fault)
		case folderYear == nil:
			p.badFolders.error("No year folder found in %s", u)
		case date.UTC().Year() != *folderYear:
			p.badFolders.error("%s should be in folder %d", u, date.UTC().Year())
		}
		current, fault := p.extractTime(doc, `current_release_date`, u)
		if fault != "" {
			p.badChanges.error(fault)
		} else {
			p.timesAdv[f.URL()] = current
		}

		// Check hashes
		p.badIntegrities.use()

		type hash struct {
			ext  string
			url  func() string
			hash []byte
		}
		hashes := []hash{}
		if f.SHA256URL() != "" {
			hashes = append(hashes, hash{"SHA256", f.SHA256URL, s256.Sum(nil)})
		}
		if f.SHA512URL() != "" {
			hashes = append(hashes, hash{"SHA512", f.SHA512URL, s512.Sum(nil)})
		}

		couldFetchHash := false
		hashFetchErrors := []string{}

		for _, x := range hashes {
			hu, err := url.Parse(x.url())
			if err != nil {
				lg(ErrorType, "Bad URL %s: %v", x.url(), err)
				continue
			}
			hashFile := misc.JoinURL(b, hu).String()

			p.checkTLS(hashFile)
			if res, err = client.Get(hashFile); err != nil {
				hashFetchErrors = append(hashFetchErrors, fmt.Sprintf("Fetching %s failed: %v.", hashFile, err))
				continue
			}
			if res.StatusCode != http.StatusOK {
				hashFetchErrors = append(hashFetchErrors, fmt.Sprintf("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status))
				continue
			}
			couldFetchHash = true
			h, err := func() ([]byte, error) {
				defer res.Body.Close()
				return util.HashFromReader(res.Body)
			}()
			if err != nil {
				p.badIntegrities.error("Reading %s failed: %v.", hashFile, err)
				continue
			}
			if len(h) == 0 {
				p.badIntegrities.error("No hash found in %s.", hashFile)
				continue
			}
			if !bytes.Equal(h, x.hash) {
				p.badIntegrities.error("%s hash of %s does not match %s.",
					x.ext, u, hashFile)
			}
		}

		msgType := ErrorType
		// Log only as warning, if the other hash could be fetched
		if couldFetchHash {
			msgType = WarnType
		}
		if f.IsDirectory() {
			msgType = InfoType
		}
		for _, fetchError := range hashFetchErrors {
			p.badIntegrities.add(msgType, fetchError)
		}

		// Check signature
		su, err := url.Parse(f.SignURL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f.SignURL(), err)
			continue
		}
		sigFile := misc.JoinURL(b, su).String()
		p.checkTLS(sigFile)

		p.badSignatures.use()

		if res, err = client.Get(sigFile); err != nil {
			p.badSignatures.error("Fetching %s failed: %v.", sigFile, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badSignatures.error("Fetching %s failed: status code %d (%s)",
				sigFile, res.StatusCode, res.Status)
			continue
		}

		sig, err := func() (*crypto.PGPSignature, error) {
			defer res.Body.Close()
			all, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, err
			}
			return crypto.NewPGPSignatureFromArmored(string(all))
		}()
		if err != nil {
			p.badSignatures.error("Loading signature from %s failed: %v.",
				sigFile, err)
			continue
		}

		if p.keys != nil {
			pm := crypto.NewPlainMessage(data.Bytes())
			t := crypto.GetUnixTime()
			if err := p.keys.VerifyDetached(pm, sig, t); err != nil {
				p.badSignatures.error("Signature of %s could not be verified: %v.", u, err)
			}
		}
	}

	// If we tested an existing changes.csv
	if len(p.timesAdv) > 0 && p.badChanges.used() {
		// Iterate over all files again
		for _, f := range files {
			// If there was no previous error when extracting times from advisories and we have a valid time
			if timeAdv, ok := p.timesAdv[f.URL()]; ok {
				// If there was no previous error when extracting times from changes and the file was listed in changes.csv
				if timeCha, ok := p.timesChanges[f.URL()]; ok {
					// check if the time matches
					if !timeAdv.Equal(timeCha) {
						// if not, give an error and remove the pair so it isn't reported multiple times should integrity be called again
						p.badChanges.error("Current release date in changes.csv and %s is not identical.", f.URL())
						delete(p.timesAdv, f.URL())
						delete(p.timesChanges, f.URL())
					}
				}
			}
		}
	}

	return nil
}

// extractTime extracts a time.Time value from a json document and returns it and an empty string or zero time alongside
// a string representing the error message that prevented obtaining the proper time value.
func (p *processor) extractTime(doc any, value string, u any) (time.Time, string) {
	filter := "$.document.tracking." + value
	date, err := p.expr.Eval(filter, doc)
	if err != nil {
		return time.Time{}, fmt.Sprintf("Extracting '%s' from %s failed: %v", value, u, err)
	}
	text, ok := date.(string)
	if !ok {
		return time.Time{}, fmt.Sprintf("'%s' is not a string in %s", value, u)
	}
	d, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, fmt.Sprintf("Parsing '%s' as RFC3339 failed in %s: %v", value, u, err)
	}
	return d, ""
}

// checkIndex fetches the "index.txt" and calls "checkTLS" method for HTTPS checks.
// It extracts the file names from the file and passes them to "integrity" function.
// It returns error if fetching/reading the file(s) fails, otherwise nil.
func (p *processor) checkIndex(base string, mask whereType) error {
	client := p.httpClient()

	bu, err := url.Parse(base)
	if err != nil {
		return err
	}

	index := bu.JoinPath("index.txt").String()

	p.checkTLS(index)

	p.badIndices.use()

	res, err := client.Get(index)
	if err != nil {
		p.badIndices.error("Fetching %s failed: %v", index, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		// It's optional
		if res.StatusCode != http.StatusNotFound {
			p.badIndices.error("Fetching %s failed. Status code %d (%s)",
				index, res.StatusCode, res.Status)
		} else {
			p.badIndices.error("Fetching index.txt failed: %v not found.", index)
		}
		return errContinue
	}
	p.badIndices.info("Found %v", index)

	files, err := func() ([]csaf.AdvisoryFile, error) {
		defer res.Body.Close()
		var files []csaf.AdvisoryFile
		scanner := bufio.NewScanner(res.Body)
		for line := 1; scanner.Scan(); line++ {
			u := scanner.Text()
			if _, err := url.Parse(u); err != nil {
				p.badIntegrities.error("index.txt contains invalid URL %q in line %d", u, line)
				continue
			}

			files = append(files, csaf.DirectoryAdvisoryFile{Path: u})
		}
		return files, scanner.Err()
	}()
	if err != nil {
		p.badIndices.error("Reading %s failed: %v", index, err)
		return errContinue
	}
	if len(files) == 0 {
		p.badIntegrities.warn("index.txt contains no URLs")
	}

	// Block rolie checks.
	p.labelChecker.feedLabel = ""

	return p.integrity(files, base, mask, p.badIndices.add)
}

// checkChanges fetches the "changes.csv" and calls the "checkTLS" method for HTTPs checks.
// It extracts the file content, tests the column number and the validity of the time format
// of the fields' values and if they are sorted properly. Then it passes the files to the
// "integrity" functions. It returns error if some test fails, otherwise nil.
func (p *processor) checkChanges(base string, mask whereType) error {
	bu, err := url.Parse(base)
	if err != nil {
		return err
	}
	changes := bu.JoinPath("changes.csv").String()

	p.checkTLS(changes)

	client := p.httpClient()
	res, err := client.Get(changes)

	p.badChanges.use()

	if err != nil {
		p.badChanges.error("Fetching %s failed: %v", changes, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		if res.StatusCode != http.StatusNotFound {
			// It's optional
			p.badChanges.error("Fetching %s failed. Status code %d (%s)",
				changes, res.StatusCode, res.Status)
		} else {
			p.badChanges.error("Fetching changes.csv failed: %v not found.", changes)
		}
		return errContinue
	}
	p.badChanges.info("Found %v", changes)

	times, files, err := func() ([]time.Time, []csaf.AdvisoryFile, error) {
		defer res.Body.Close()
		var times []time.Time
		var files []csaf.AdvisoryFile
		c := csv.NewReader(res.Body)
		const (
			pathColumn = 0
			timeColumn = 1
		)
		for {
			r, err := c.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, nil, err
			}
			if len(r) < 2 {
				return nil, nil, errors.New("not enough columns")
			}
			t, err := time.Parse(time.RFC3339, r[timeColumn])
			if err != nil {
				return nil, nil, err
			}
			// Apply date range filtering.
			if accept := p.cfg.Range; accept != nil && !accept.Contains(t) {
				continue
			}
			path := r[pathColumn]

			times, files =
				append(times, t),
				append(files, csaf.DirectoryAdvisoryFile{Path: path})
			p.timesChanges[path] = t
		}
		return times, files, nil
	}()
	if err != nil {
		p.badChanges.error("Reading %s failed: %v", changes, err)
		return errContinue
	}

	if len(files) == 0 {
		var filtered string
		if p.cfg.Range != nil {
			filtered = " (maybe filtered out by time interval)"
		}
		p.badChanges.warn("no entries in changes.csv found" + filtered)
	}

	if !sort.SliceIsSorted(times, func(i, j int) bool {
		return times[j].Before(times[i])
	}) {
		p.badChanges.error("%s is not sorted in descending order", changes)
	}

	// Block rolie checks.
	p.labelChecker.feedLabel = ""

	return p.integrity(files, base, mask, p.badChanges.add)
}

// empty checks if list of strings contains at least one none empty string.
func empty(arr []string) bool {
	for _, s := range arr {
		if s != "" {
			return false
		}
	}
	return true
}

func (p *processor) checkCSAFs(_ string) error {
	// Check for ROLIE
	rolie, err := p.expr.Eval("$.distributions[*].rolie.feeds", p.pmd)
	if err != nil {
		return err
	}

	fs, hasRolie := rolie.([]any)
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]csaf.Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			p.badProviderMetadata.error("ROLIE feeds are not compatible: %v.", err)
		} else if err := p.processROLIEFeeds(feeds); err != nil {
			if err != errContinue {
				return err
			}
		}
		// check for service category document
		p.serviceCheck(feeds)
	} else {
		p.badROLIEFeed.use()
		p.badROLIEFeed.error("ROLIE feed based distribution was not used.")
		p.badROLIECategory.use()
		p.badROLIECategory.warn("No ROLIE category document found.")
		p.badROLIEService.use()
		p.badROLIEService.warn("No ROLIE service document found.")
	}

	// No rolie feeds -> try directory_urls.
	directoryURLs, err := p.expr.Eval(
		"$.distributions[*].directory_url", p.pmd)

	var dirURLs []string

	if err != nil {
		p.badProviderMetadata.warn("extracting directory URLs failed: %v.", err)
	} else {
		var ok bool
		dirURLs, ok = util.AsStrings(directoryURLs)
		if !ok {
			p.badProviderMetadata.warn("directory URLs are not strings.")
		}
	}

	// Not found -> fall back to PMD url
	if empty(dirURLs) {
		pmdURL, err := url.Parse(p.pmdURL)
		if err != nil {
			return err
		}
		baseURL, err := util.BaseURL(pmdURL)
		if err != nil {
			return err
		}
		dirURLs = []string{baseURL}
	}

	for _, base := range dirURLs {
		if base == "" {
			continue
		}
		if err := p.checkIndex(base, indexMask); err != nil && err != errContinue {
			return err
		}

		if err := p.checkChanges(base, changesMask); err != nil && err != errContinue {
			return err
		}
	}

	if !p.badFolders.used() {
		p.badFolders.use()
		p.badFolders.error("No checks performed on whether files are within the right folders.")
	}
	return nil
}

func (p *processor) checkMissing(string) error {
	var maxMask whereType

	for _, v := range p.alreadyChecked {
		maxMask |= v
	}

	var files []string

	for f, v := range p.alreadyChecked {
		if v != maxMask {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		v := p.alreadyChecked[f]
		var where []string
		// mistake contains which requirements are broken
		var mistake whereType
		for mask := rolieMask; mask <= listingMask; mask <<= 1 {
			if maxMask&mask == mask {
				var in string
				if v&mask == mask {
					in = "in"
				} else {
					in = "not in"
					// Which file is missing entries?
					mistake |= mask
				}
				where = append(where, in+" "+mask.String())
			}
		}
		// List error in all appropriate categories
		if mistake&(rolieMask|indexMask|changesMask|listingMask) == 0 {
			continue
		}
		joined := strings.Join(where, ", ")
		report := func(mask whereType, msgs *topicMessages) {
			if mistake&mask != 0 {
				msgs.error("%s %s", f, joined)
			}
		}
		report(rolieMask, &p.badROLIEFeed)
		report(indexMask, &p.badIndices)
		report(changesMask, &p.badChanges)
		report(listingMask, &p.badDirListings)
	}
	return nil
}

// checkInvalid goes over all found adivisories URLs and checks
// if file name conforms to standard.
func (p *processor) checkInvalid(string) error {
	p.badDirListings.use()
	var invalids []string

	for f := range p.alreadyChecked {
		if !util.ConformingFileName(filepath.Base(f)) {
			invalids = append(invalids, f)
		}
	}

	if len(invalids) > 0 {
		sort.Strings(invalids)
		p.badDirListings.error("advisories with invalid file names: %s",
			strings.Join(invalids, ", "))
	}

	return nil
}

// checkListing goes over all found adivisories URLs and checks
// if their parent directory is listable.
func (p *processor) checkListing(string) error {
	p.badDirListings.use()

	pgs := pages{}

	var unlisted []string

	badDirs := util.Set[string]{}

	if len(p.alreadyChecked) == 0 {
		p.badDirListings.info("No directory listings found.")
	}

	for f := range p.alreadyChecked {
		found, err := pgs.listed(f, p, badDirs)
		if err != nil && err != errContinue {
			return err
		}
		if !found {
			unlisted = append(unlisted, f)
		}
	}

	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		p.badDirListings.error("Not listed advisories: %s",
			strings.Join(unlisted, ", "))
	}

	return nil
}

// checkWhitePermissions checks if the TLP:WHITE advisories are
// available with unprotected access.
func (p *processor) checkWhitePermissions(string) error {
	var ids []string
	for id, open := range p.labelChecker.whiteAdvisories {
		if !open {
			ids = append(ids, id.String())
		}
	}

	if len(ids) == 0 {
		return nil
	}

	sort.Strings(ids)

	p.badWhitePermissions.error(
		"TLP:WHITE advisories with ids %s are only available access-protected.",
		strings.Join(ids, ", "))

	return nil
}

// checkProviderMetadata checks provider-metadata.json. If it exists,
// decodes, and validates against the JSON schema.
// According to the result, the respective error messages added to
// badProviderMetadata.
func (p *processor) checkProviderMetadata(domain string) bool {
	p.badProviderMetadata.use()

	client := p.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)

	lpmd := loader.Load(domain)

	for i := range lpmd.Messages {
		p.badProviderMetadata.warn(
			"Unexpected situation while loading provider-metadata.json: " +
				lpmd.Messages[i].Message)
	}

	if !lpmd.Valid() {
		return false
	}

	p.pmdURL = lpmd.URL
	p.pmd256 = lpmd.Hash
	p.pmd = lpmd.Document

	return true
}

// checkSecurity checks the security.txt file by making HTTP request to fetch it.
// It checks the existence of the CSAF field in the file content and tries to fetch
// the value of this field. Returns an empty string if no error was encountered,
// the errormessage otherwise.
func (p *processor) checkSecurity(domain string, legacy bool) (int, string) {
	folder := "https://" + domain + "/"
	if !legacy {
		folder = folder + ".well-known/"
	}
	msg := p.checkSecurityFolder(folder)
	if msg == "" {
		if !legacy {
			return 0, "Found valid security.txt within the well-known directory"
		}
		return 2, "Found valid security.txt in the legacy location"
	}
	return 1, folder + "security.txt: " + msg
}

// checkSecurityFolder checks the security.txt in a given folder.
func (p *processor) checkSecurityFolder(folder string) string {
	client := p.httpClient()
	path := folder + "security.txt"
	res, err := client.Get(path)
	if err != nil {
		return fmt.Sprintf("Fetching %s failed: %v", path, err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
	}

	u, err := func() (string, error) {
		defer res.Body.Close()
		lines, err := csaf.ExtractProviderURL(res.Body, false)
		var u string
		if len(lines) > 0 {
			u = lines[0]
		}
		return u, err
	}()
	if err != nil {
		return fmt.Sprintf("Error while reading security.txt: %v", err)
	}
	if u == "" {
		return "No CSAF line found in security.txt."
	}

	// Try to load
	up, err := url.Parse(u)
	if err != nil {
		return fmt.Sprintf("CSAF URL '%s' invalid: %v", u, err)
	}

	base, err := url.Parse(folder)
	if err != nil {
		return err.Error()
	}

	u = misc.JoinURL(base, up).String()
	p.checkTLS(u)
	if res, err = client.Get(u); err != nil {
		return fmt.Sprintf("Cannot fetch %s from security.txt: %v", u, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			u, res.StatusCode, res.Status)
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		return fmt.Sprintf("Reading %s failed: %v", u, err)
	}

	if !bytes.Equal(h.Sum(nil), p.pmd256) {
		return fmt.Sprintf("Content of %s from security.txt is not "+
			"identical to .well-known/csaf/provider-metadata.json", u)
	}
	return ""
}

// checkDNS checks if the "csaf.data.security.domain.tld" DNS record is available
// and serves the "provider-metadata.json".
func (p *processor) checkDNS(domain string) {
	p.badDNSPath.use()
	client := p.httpClient()
	path := "https://csaf.data.security." + domain
	res, err := client.Get(path)
	if err != nil {
		p.badDNSPath.add(ErrorType,
			fmt.Sprintf("Fetching %s failed: %v", path, err))
		return
	}
	if res.StatusCode != http.StatusOK {
		p.badDNSPath.add(ErrorType, fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status))
	}
	hash := sha256.New()
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		p.badDNSPath.add(ErrorType,
			fmt.Sprintf("Error while reading the response from %s", path))
	}
	hash.Write(content)
	if !bytes.Equal(hash.Sum(nil), p.pmd256) {
		p.badDNSPath.add(ErrorType,
			fmt.Sprintf("%s does not serve the same provider-metadata.json as previously found",
				path))
	}
}

// checkWellknown checks if the provider-metadata.json file is
// available under the /.well-known/csaf/ directory.
func (p *processor) checkWellknown(domain string) {

	p.badWellknownMetadata.use()
	client := p.httpClient()
	path := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	res, err := client.Get(path)
	if err != nil {
		p.badWellknownMetadata.add(ErrorType,
			fmt.Sprintf("Fetching %s failed: %v", path, err))
	}
	if res.StatusCode != http.StatusOK {
		p.badWellknownMetadata.add(ErrorType, fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status))
	}
}

// checkWellknownSecurityDNS
//  1. checks if the provider-metadata.json file is
//     available under the /.well-known/csaf/ directory.
//  2. Then it checks the security.txt file by making HTTP request to fetch it.
//  3. After that it checks the existence of the CSAF field in the file
//     content and tries to fetch the value of this field.
//  4. Finally it checks if the "csaf.data.security.domain.tld" DNS record
//     is available and serves the "provider-metadata.json".
//
// For the security.txt checks, it first checks the default location.
// Should this lookup fail, a warning is will be given and a lookup
// for the legacy location will be made. If this fails as well, then an
// error is given.
func (p *processor) checkWellknownSecurityDNS(domain string) error {
	p.checkWellknown(domain)
	// Security check for well known (default) and legacy location
	warnings, sDMessage := p.checkSecurity(domain, false)
	// if the security.txt under .well-known was not okay
	// check for a security.txt within its legacy location
	sLMessage := ""
	if warnings == 1 {
		warnings, sLMessage = p.checkSecurity(domain, true)
	}

	p.badSecurity.use()

	// Report about Securitytxt:
	// Only report about default location if it was succesful (0).
	// Report default and legacy as errors if neither was succesful (1).
	// Warn about missing security in the default position if not found
	// but found in the legacy location, and inform about finding it there (2).
	switch warnings {
	case 0:
		p.badSecurity.add(InfoType, sDMessage)
	case 1:
		p.badSecurity.add(ErrorType, sDMessage)
		p.badSecurity.add(ErrorType, sLMessage)
	case 2:
		p.badSecurity.add(WarnType, sDMessage)
		p.badSecurity.add(InfoType, sLMessage)
	}

	p.checkDNS(domain)

	return nil
}

// checkPGPKeys checks if the OpenPGP keys are available and valid, fetches
// the remote pubkeys and compares the fingerprints.
// As a result of these checks respective error messages are passed
// to badPGP methods. It returns nil if all checks are passed.
func (p *processor) checkPGPKeys(_ string) error {
	p.badPGPs.use()

	src, err := p.expr.Eval("$.public_openpgp_keys", p.pmd)
	if err != nil {
		p.badPGPs.warn("No public OpenPGP keys found: %v.", err)
		return errContinue
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		p.badPGPs.error("Invalid public OpenPGP keys: %v.", err)
		return errContinue
	}

	if len(keys) == 0 {
		p.badPGPs.info("No public OpenPGP keys found.")
		return errContinue
	}

	// Try to load

	client := p.httpClient()

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	base.Path = ""

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			p.badPGPs.error("Missing URL for fingerprint %x.", key.Fingerprint)
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			p.badPGPs.error("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		u := misc.JoinURL(base, up).String()
		p.checkTLS(u)

		res, err := client.Get(u)
		if err != nil {
			p.badPGPs.error("Fetching public OpenPGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badPGPs.error("Fetching public OpenPGP key %s status code: %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()
		if err != nil {
			p.badPGPs.error("Reading public OpenPGP key %s failed: %v", u, err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			p.badPGPs.error("Given Fingerprint (%q) of public OpenPGP key %q does not match remotely loaded (%q).", string(key.Fingerprint), u, ckey.GetFingerprint())
			continue
		}
		if p.keys == nil {
			if keyring, err := crypto.NewKeyRing(ckey); err != nil {
				p.badPGPs.error("Creating store for public OpenPGP key %s failed: %v.", u, err)
			} else {
				p.keys = keyring
			}
		} else {
			p.keys.AddKey(ckey)
		}
	}

	if p.keys == nil {
		p.badPGPs.info("No OpenPGP keys loaded.")
	}
	return nil
}
