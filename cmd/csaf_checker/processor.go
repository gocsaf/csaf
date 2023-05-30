// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
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

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

// topicMessages stores the collected topicMessages for a specific topic.
type topicMessages []Message

type processor struct {
	opts      *options
	validator csaf.RemoteValidator
	client    util.Client
	ageAccept func(time.Time) bool

	redirects      map[string][]string
	noneTLS        map[string]struct{}
	alreadyChecked map[string]whereType
	pmdURL         string
	pmd256         []byte
	pmd            any
	keys           *crypto.KeyRing

	invalidAdvisories    topicMessages
	badFilenames         topicMessages
	badIntegrities       topicMessages
	badPGPs              topicMessages
	badSignatures        topicMessages
	badProviderMetadata  topicMessages
	badSecurity          topicMessages
	badIndices           topicMessages
	badChanges           topicMessages
	badFolders           topicMessages
	badWellknownMetadata topicMessages
	badDNSPath           topicMessages
	badDirListings       topicMessages
	badROLIEfeed         topicMessages

	expr *util.PathEval
}

type completion struct {
	unlabeled tlpls
	white     tlpls
	green     tlpls
	amber     tlpls
	red       tlpls
	mismatch  []matches
}

// When going through all feeds, the summary feed is determined after going through all feeds.
// As such, save all mismatched non-error feeds here to easily determine whether to put this information 
// into info or warning.
type matches struct {
	feed string
	entry string
}
// tlpls holds all ROLIE feeds of a given tlp level that contain all entries of their given level
// as well as all entries of that level, meaning for a given tlpls all entries in feeds contain all entries
// in entries
type tlpls struct {
	feeds   []string
	entries []string
}

// reporter is implemented by any value that has a report method.
// The implementation of the report controls how to test
// the respective requirement and generate the report.
type reporter interface {
	report(*processor, *Domain)
}

var (
	// errContinue indicates that the current check should continue.
	errContinue = errors.New("continue")
	// errStop indicates that the current check should stop.
	errStop = errors.New("stop")
)

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

// use signals that we going to use this topic.
func (m *topicMessages) use() {
	if *m == nil {
		*m = []Message{}
	}
}

// reset resets the messages to this topic.
func (m *topicMessages) reset() { *m = nil }

// used returns true if we have used this topic.
func (m *topicMessages) used() bool { return *m != nil }

// newProcessor returns a processor structure after assigning the given options to the opts attribute
// and initializing the "alreadyChecked" and "expr" fields.
func newProcessor(opts *options) (*processor, error) {

	var validator csaf.RemoteValidator

	if opts.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     opts.RemoteValidator,
			Presets: opts.RemoteValidatorPresets,
			Cache:   opts.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return nil, fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
	}

	return &processor{
		opts:           opts,
		alreadyChecked: map[string]whereType{},
		expr:           util.NewPathEval(),
		ageAccept:      ageAccept(opts),
		validator:      validator,
	}, nil
}

// close closes external ressources of the processor.
func (p *processor) close() {
	if p.validator != nil {
		p.validator.Close()
		p.validator = nil
	}
}

func ageAccept(opts *options) func(time.Time) bool {
	if opts.Years == nil {
		return nil
	}
	good := time.Now().AddDate(-int(*opts.Years), 0, 0)
	return func(t time.Time) bool {
		return !t.Before(good)
	}
}

// clean clears the fields values of the given processor.
func (p *processor) clean() {
	p.redirects = nil
	p.noneTLS = nil
	for k := range p.alreadyChecked {
		delete(p.alreadyChecked, k)
	}
	p.pmdURL = ""
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil

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
	p.badROLIEfeed.reset()
}

// run calls checkDomain function for each domain in the given "domains" parameter.
// Then it calls the report method on each report from the given "reporters" parameter for each domain.
// It returns a pointer to the report and nil, otherwise an error.
func (p *processor) run(domains []string) (*Report, error) {

	report := Report{
		Date:    ReportTime{Time: time.Now().UTC()},
		Version: util.SemVersion,
	}

	for _, d := range domains {
		if p.checkProviderMetadata(d) {
			if err := p.checkDomain(d); err != nil {
				if err == errContinue || err == errStop {
					continue
				}
				return nil, err
			}
		}
		domain := &Domain{Name: d}

		if err := p.fillMeta(domain); err != nil {
			log.Printf("Filling meta data failed: %v\n", err)
			// reporters depend on role.
			continue
		}

		for _, r := range buildReporters(*domain.Role) {
			r.report(p, domain)
		}

		report.Domains = append(report.Domains, domain)
		p.clean()
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
	}

	checks = append(checks,
		(*processor).checkCSAFs,
		(*processor).checkMissing,
		(*processor).checkInvalid,
		(*processor).checkListing,
	)

	return checks
}

func (p *processor) checkDomain(domain string) error {

	for _, check := range p.domainChecks(domain) {
		if err := check(p, domain); err != nil && err != errContinue {
			if err == errStop {
				return nil
			}
			return err
		}
	}

	return nil
}

// checkTLS parses the given URL to check its schema, as a result it sets
// the value of "noneTLS" field if it is not HTTPS.
func (p *processor) checkTLS(u string) {
	if p.noneTLS == nil {
		p.noneTLS = map[string]struct{}{}
	}
	if x, err := url.Parse(u); err == nil && x.Scheme != "https" {
		p.noneTLS[u] = struct{}{}
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

func (p *processor) httpClient() util.Client {

	if p.client != nil {
		return p.client
	}

	hClient := http.Client{}

	hClient.CheckRedirect = p.checkRedirect

	var tlsConfig tls.Config
	if p.opts.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(p.opts.clientCerts) != 0 {
		tlsConfig.Certificates = p.opts.clientCerts
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := util.Client(&hClient)

	// Add extra headers.
	if len(p.opts.ExtraHeader) > 0 {
		client = &util.HeaderClient{
			Client: client,
			Header: p.opts.ExtraHeader,
		}
	}

	// Add optional URL logging.
	if p.opts.Verbose {
		client = &util.LoggingClient{Client: client}
	}

	// Add optional rate limiting.
	if p.opts.Rate != nil {
		client = &util.LimitingClient{
			Client:  client,
			Limiter: rate.NewLimiter(rate.Limit(*p.opts.Rate), 1),
		}
	}

	p.client = client
	return p.client
}

var yearFromURL = regexp.MustCompile(`.*/(\d{4})/[^/]+$`)

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

	makeAbs := func(u *url.URL) *url.URL {
		if u.IsAbs() {
			return u
		}
		return b.JoinPath(u.String())
	}

	for _, f := range files {
		fp, err := url.Parse(f.URL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f, err)
			continue
		}
		fp = makeAbs(fp)

		u := b.ResolveReference(fp).String()
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
			// Check if we are in checking time interval.
			if p.ageAccept != nil && !p.ageAccept(
				time.Date(
					year, 12, 31, // Assume last day of year.
					23, 59, 59, 0, // 23:59:59
					time.UTC)) {
				continue
			}
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

		// Warn if we do not get JSON.
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			lg(WarnType,
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
			p.invalidAdvisories.error("%s: %v\n", u, err)
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

		// Check if file is in the right folder.
		p.badFolders.use()

		if date, err := p.expr.Eval(
			`$.document.tracking.initial_release_date`, doc); err != nil {
			p.badFolders.error(
				"Extracting 'initial_release_date' from %s failed: %v", u, err)
		} else if text, ok := date.(string); !ok {
			p.badFolders.error("'initial_release_date' is not a string in %s", u)
		} else if d, err := time.Parse(time.RFC3339, text); err != nil {
			p.badFolders.error(
				"Parsing 'initial_release_date' as RFC3339 failed in %s: %v", u, err)
		} else if folderYear == nil {
			p.badFolders.error("No year folder found in %s", u)
		} else if d.UTC().Year() != *folderYear {
			p.badFolders.error("%s should be in folder %d", u, d.UTC().Year())
		}

		// Check hashes
		p.badIntegrities.use()

		for _, x := range []struct {
			ext  string
			url  func() string
			hash []byte
		}{
			{"SHA256", f.SHA256URL, s256.Sum(nil)},
			{"SHA512", f.SHA512URL, s512.Sum(nil)},
		} {
			hu, err := url.Parse(x.url())
			if err != nil {
				lg(ErrorType, "Bad URL %s: %v", x.url(), err)
				continue
			}
			hu = makeAbs(hu)
			hashFile := b.ResolveReference(hu).String()
			p.checkTLS(hashFile)
			if res, err = client.Get(hashFile); err != nil {
				p.badIntegrities.error("Fetching %s failed: %v.", hashFile, err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				p.badIntegrities.error("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status)
				continue
			}
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

		// Check signature
		su, err := url.Parse(f.SignURL())
		if err != nil {
			lg(ErrorType, "Bad URL %s: %v", f.SignURL(), err)
			continue
		}
		su = makeAbs(su)
		sigFile := b.ResolveReference(su).String()
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
	return nil
}

func (p *processor) processROLIEFeed(feed string) error {
	client := p.httpClient()
	res, err := client.Get(feed)
	p.badDirListings.use()
	if err != nil {
		p.badProviderMetadata.error("Cannot fetch feed %s: %v", feed, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badProviderMetadata.warn("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return errContinue
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
		return errContinue
	}
	errors, err := csaf.ValidateROLIE(rolieDoc)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		p.badProviderMetadata.error("%s: Validating against JSON schema failed:", feed)
		for _, msg := range errors {
			p.badProviderMetadata.error(strings.ReplaceAll(msg, `%`, `%%`))
		}
	}

	feedURL, err := url.Parse(feed)
	if err != nil {
		p.badProviderMetadata.error("Bad base path: %v", err)
		return errContinue
	}

	base, err := util.BaseURL(feedURL)
	if err != nil {
		p.badProviderMetadata.error("Bad base path: %v", err)
		return errContinue
	}

	// Extract the CSAF files from feed.
	var files []csaf.AdvisoryFile

	rfeed.Entries(func(entry *csaf.Entry) {

		// Filter if we have date checking.
		if p.ageAccept != nil {
			if pub := time.Time(entry.Published); !pub.IsZero() && !p.ageAccept(pub) {
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

		if sha256 != "" || sha512 != "" || sign != "" {
			file = csaf.HashedAdvisoryFile{url, sha256, sha512, sign}
		} else {
			file = csaf.PlainAdvisoryFile(url)
		}

		files = append(files, file)
	})
	if err := p.integrity(files, base, rolieMask, p.badProviderMetadata.add); err != nil &&
		err != errContinue {
		return err
	}

	return nil
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
			p.badIndices.warn("Fetching index.txt failed: %v not found.", index)
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
			files = append(files, csaf.PlainAdvisoryFile(u))
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
			p.badChanges.warn("Fetching changes.csv failed: %v not found.", changes)
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
			if p.ageAccept != nil && !p.ageAccept(t) {
				continue
			}
			path := r[pathColumn]
			times, files =
				append(times, t),
				append(files, csaf.PlainAdvisoryFile(path))
		}
		return times, files, nil
	}()
	if err != nil {
		p.badChanges.error("Reading %s failed: %v", changes, err)
		return errContinue
	}

	if len(files) == 0 {
		var filtered string
		if p.ageAccept != nil {
			filtered = " (maybe filtered out by time interval)"
		}
		p.badChanges.warn("no entries in changes.csv found" + filtered)
	}

	if !sort.SliceIsSorted(times, func(i, j int) bool {
		return times[j].Before(times[i])
	}) {
		p.badChanges.error("%s is not sorted in descending order", changes)
	}

	return p.integrity(files, base, mask, p.badChanges.add)
}

func (p *processor) processROLIEFeeds(feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	p.badROLIEfeed.use()
	// mark which ROLIE feed tlp levels have been used
	tlpUsed := make(map[string]bool)
//	var ca completion
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.TLPLabel == nil {
				tlpUsed["unlabeled"] = true
			} else {
				tlpUsed[string(*feed.TLPLabel)] = true
			}
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			p.checkTLS(feedURL)
			if err := p.processROLIEFeed(feedURL); err != nil && err != errContinue {
				return err
			}
		}
	}
	if !(tlpUsed["WHITE"] || tlpUsed["GREEN"] || tlpUsed["Unlabeled"]) {
		p.badROLIEfeed.error("One ROLIE feed with a TLP:WHITE, TLP:GREEN or unlabeled tlp must exist, but none were found.")
	}
	return nil
}

func (p *processor) checkCompletion(ca completion, tlpf string, tlpe string, feedName string, entryName string){

	// Assign int to tlp levels for easy comparison
	var tlpfn int
	var tlpen int
	switch tlpf {
	case "WHITE":
		tlpfn = 1
	case "GREEN":
		tlpfn = 2
	case "AMBER":
		tlpfn = 3
	case "RED":
		tlpfn = 4
	default:
		tlpfn = 0
	}
	switch tlpe {
        case "WHITE":
                tlpen = 1
        case "GREEN":
                tlpen = 2
        case "AMBER":
                tlpen = 3
        case "RED":
                tlpen = 4
        default:
                tlpen = 0
        }

	// If entry shows up in feed of higher tlp level, save the combi to evaluate it when we know if feed
	// is summary feed or not
	if tlpen < tlpfn {
		var match matches
		match.feed = feedName
		match.entry = entryName
		ca.mismatch = append(ca.mismatch, match)
	}
	// Must not happen, give error
	if tlpen > tlpfn {
		p.badROLIEfeed.error("%s of TLP level %s must not be listed in feed %s of TLP level %s", entryName, tlpe, feedName, tlpf) 
	}

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
		for mask := rolieMask; mask <= listingMask; mask <<= 1 {
			if maxMask&mask == mask {
				var in string
				if v&mask == mask {
					in = "in"
				} else {
					in = "not in"
				}
				where = append(where, in+" "+mask.String())
			}
		}
		p.badIntegrities.error("%s %s", f, strings.Join(where, ", "))
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

	badDirs := map[string]struct{}{}

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
		// TODO: Filter depending on the role.
		p.badProviderMetadata.error(lpmd.Messages[i].Message)
	}

	if !lpmd.Valid() {
		p.badProviderMetadata.error("No valid provider-metadata.json found.")
		p.badProviderMetadata.error("STOPPING here - cannot perform other checks.")
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
func (p *processor) checkSecurity(domain string) string {

	client := p.httpClient()
	path := "https://" + domain + "/.well-known/security.txt"
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

	base, err := url.Parse("https://" + domain + "/.well-known/")
	if err != nil {
		return err.Error()
	}

	u = base.ResolveReference(up).String()
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
// It returns an empty string if all checks are passed, otherwise the errormessage.
func (p *processor) checkDNS(domain string) string {

	client := p.httpClient()
	path := "https://csaf.data.security." + domain
	res, err := client.Get(path)
	if err != nil {
		return fmt.Sprintf("Fetching %s failed: %v", path, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)

	}
	hash := sha256.New()
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Sprintf("Error while reading the response from %s", path)
	}
	hash.Write(content)
	if !bytes.Equal(hash.Sum(nil), p.pmd256) {
		return fmt.Sprintf("%s does not serve the same provider-metadata.json as previously found", path)
	}
	return ""
}

// checkWellknownMetadataReporter checks if the provider-metadata.json file is
// available under the /.well-known/csaf/ directory. Returns the errormessage if
// an error was encountered, or an empty string otherwise
func (p *processor) checkWellknown(domain string) string {

	client := p.httpClient()
	path := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	res, err := client.Get(path)
	if err != nil {
		return fmt.Sprintf("Fetching %s failed: %v", path, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Sprintf("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
	}
	return ""
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
// /
// If all three checks fail, errors are given,
// otherwise warnings for all failed checks.
// The function returns nil, unless errors outside the checks were found.
// In that case, errors are returned.
func (p *processor) checkWellknownSecurityDNS(domain string) error {

	warningsW := p.checkWellknown(domain)
	warningsS := p.checkSecurity(domain)
	warningsD := p.checkDNS(domain)

	p.badWellknownMetadata.use()
	p.badSecurity.use()
	p.badDNSPath.use()

	var kind MessageType
	if warningsS == "" || warningsD == "" || warningsW == "" {
		kind = WarnType
	} else {
		kind = ErrorType
	}

	if warningsW != "" {
		p.badWellknownMetadata.add(kind, warningsW)
	}
	if warningsS != "" {
		p.badSecurity.add(kind, warningsS)
	}
	if warningsD != "" {
		p.badDNSPath.add(kind, warningsD)
	}
	return nil
}

// checkPGPKeys checks if the OpenPGP keys are available and valid, fetches
// the the remotely keys and compares the fingerprints.
// As a result of these a respective error messages are passed to badPGP method
// in case of errors. It returns nil if all checks are passed.
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

		u := base.ResolveReference(up).String()
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
			p.badPGPs.error("Fingerprint of public OpenPGP key %s does not match remotely loaded.", u)
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
