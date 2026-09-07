package comparison

import "encoding/json"

type Root struct {
	Schema   string `json:"$schema"`
	Document struct {
		Acknowledgments   AcknowledgmentsT `json:"acknowledgments,omitempty"`
		AggregateSeverity *struct {
			Namespace string `json:"namespace,omitempty"`
			Text      string `json:"text"`
		} `json:"aggregate_severity,omitempty"`
		Category     string `json:"category"`
		CsafVersion  string `json:"csaf_version"`
		Distribution struct {
			SharingGroup *struct {
				Id   string `json:"id"`
				Name string `json:"name,omitempty"`
			} `json:"sharing_group,omitempty"`
			Text string `json:"text,omitempty"`
			Tlp  struct {
				Label string `json:"label"`
				Url   string `json:"url,omitempty"`
			} `json:"tlp"`
		} `json:"distribution"`
		Lang              LangT  `json:"lang,omitempty"`
		LicenseExpression string `json:"license_expression,omitempty"`
		Notes             NotesT `json:"notes,omitempty"`
		Publisher         struct {
			Category string `json:"category"`
			Contact  *struct {
				Details             string `json:"details,omitempty"`
				Email               string `json:"email,omitempty"`
				PublicOpenpgpKeyUrl string `json:"public_openpgp_key_url,omitempty"`
			} `json:"contact,omitempty"`
			IssuingAuthority string `json:"issuing_authority,omitempty"`
			Name             string `json:"name"`
			Namespace        string `json:"namespace"`
		} `json:"publisher"`
		References ReferencesT `json:"references,omitempty"`
		SourceLang LangT       `json:"source_lang,omitempty"`
		Title      string      `json:"title"`
		Tracking   struct {
			Aliases            []string `json:"aliases,omitempty"`
			CurrentReleaseDate string   `json:"current_release_date"`
			Generator          *struct {
				Date   string `json:"date,omitempty"`
				Engine struct {
					Name    string `json:"name"`
					Version string `json:"version,omitempty"`
				} `json:"engine"`
			} `json:"generator,omitempty"`
			Id                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			RevisionHistory    []struct {
				Date          string   `json:"date"`
				LegacyVersion string   `json:"legacy_version,omitempty"`
				Number        VersionT `json:"number"`
				Summary       string   `json:"summary"`
			} `json:"revision_history"`
			Status  string   `json:"status"`
			Version VersionT `json:"version"`
		} `json:"tracking"`
		XExtensions ExtensionsT `json:"x_extensions,omitempty"`
	} `json:"document"`
	ProductTree *struct {
		Branches         BranchesT           `json:"branches,omitempty"`
		FullProductNames []*FullProductNameT `json:"full_product_names,omitempty"`
		ProductGroups    []*struct {
			GroupId    ProductGroupIdT `json:"group_id"`
			ProductIds []ProductIdT    `json:"product_ids"`
			Summary    string          `json:"summary,omitempty"`
		} `json:"product_groups,omitempty"`
		ProductPaths []*struct {
			BeginningProductReference ProductIdT       `json:"beginning_product_reference"`
			FullProductName           FullProductNameT `json:"full_product_name"`
			Subpaths                  []SubpathT       `json:"subpaths"`
		} `json:"product_paths,omitempty"`
	} `json:"product_tree,omitempty"`
	Vulnerabilities []*struct {
		Acknowledgments AcknowledgmentsT `json:"acknowledgments,omitempty"`
		Cve             string           `json:"cve,omitempty"`
		Cwes            []*struct {
			Id      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"cwes,omitempty"`
		DisclosureDate              string `json:"disclosure_date,omitempty"`
		DiscoveryDate               string `json:"discovery_date,omitempty"`
		FirstKnownExploitationDates []*struct {
			Date             string         `json:"date"`
			ExploitationDate string         `json:"exploitation_date"`
			GroupIds         ProductGroupsT `json:"group_ids,omitempty"`
			ProductIds       ProductsT      `json:"product_ids,omitempty"`
		} `json:"first_known_exploitation_dates,omitempty"`
		Flags []*struct {
			Date       string         `json:"date,omitempty"`
			GroupIds   ProductGroupsT `json:"group_ids,omitempty"`
			Label      string         `json:"label"`
			ProductIds ProductsT      `json:"product_ids,omitempty"`
		} `json:"flags,omitempty"`
		Ids []*struct {
			GroupIds   ProductGroupsT `json:"group_ids,omitempty"`
			ProductIds ProductsT      `json:"product_ids,omitempty"`
			SystemName string         `json:"system_name"`
			Text       string         `json:"text"`
		} `json:"ids,omitempty"`
		Involvements []*struct {
			Contact    string         `json:"contact,omitempty"`
			Date       string         `json:"date,omitempty"`
			GroupIds   ProductGroupsT `json:"group_ids,omitempty"`
			Party      string         `json:"party"`
			ProductIds ProductsT      `json:"product_ids,omitempty"`
			Status     string         `json:"status"`
			Summary    string         `json:"summary,omitempty"`
		} `json:"involvements,omitempty"`
		Metrics []*struct {
			Content struct {
				CvssV2 json.RawMessage `json:"cvss_v2,omitempty"`
				CvssV3 json.RawMessage `json:"cvss_v3,omitempty"`
				CvssV4 json.RawMessage `json:"cvss_v4,omitempty"`
				Epss   *struct {
					Percentile  string `json:"percentile"`
					Probability string `json:"probability"`
					Timestamp   string `json:"timestamp"`
				} `json:"epss,omitempty"`
				QualitativeSeverityRating string          `json:"qualitative_severity_rating,omitempty"`
				SsvcV2                    json.RawMessage `json:"ssvc_v2,omitempty"`
				XExtensions               ExtensionsT     `json:"x_extensions,omitempty"`
			} `json:"content"`
			Products ProductsT `json:"products"`
			Source   string    `json:"source,omitempty"`
		} `json:"metrics,omitempty"`
		Notes         NotesT `json:"notes,omitempty"`
		ProductStatus *struct {
			FirstAffected      ProductsT `json:"first_affected,omitempty"`
			FirstFixed         ProductsT `json:"first_fixed,omitempty"`
			Fixed              ProductsT `json:"fixed,omitempty"`
			KnownAffected      ProductsT `json:"known_affected,omitempty"`
			KnownNotAffected   ProductsT `json:"known_not_affected,omitempty"`
			LastAffected       ProductsT `json:"last_affected,omitempty"`
			Recommended        ProductsT `json:"recommended,omitempty"`
			UnderInvestigation ProductsT `json:"under_investigation,omitempty"`
			Unknown            ProductsT `json:"unknown,omitempty"`
		} `json:"product_status,omitempty"`
		References   ReferencesT `json:"references,omitempty"`
		Remediations []*struct {
			Category        string         `json:"category"`
			Date            string         `json:"date,omitempty"`
			Details         string         `json:"details"`
			Entitlements    []string       `json:"entitlements,omitempty"`
			GroupIds        ProductGroupsT `json:"group_ids,omitempty"`
			ProductIds      ProductsT      `json:"product_ids,omitempty"`
			RestartRequired *struct {
				Category string `json:"category"`
				Details  string `json:"details,omitempty"`
			} `json:"restart_required,omitempty"`
			Url string `json:"url,omitempty"`
		} `json:"remediations,omitempty"`
		Threats []*struct {
			Category   string         `json:"category"`
			Date       string         `json:"date,omitempty"`
			Details    string         `json:"details"`
			GroupIds   ProductGroupsT `json:"group_ids,omitempty"`
			ProductIds ProductsT      `json:"product_ids,omitempty"`
		} `json:"threats,omitempty"`
		Title       string      `json:"title,omitempty"`
		XExtensions ExtensionsT `json:"x_extensions,omitempty"`
	} `json:"vulnerabilities,omitempty"`
	XExtensions ExtensionsT `json:"x_extensions,omitempty"`
}

type AcknowledgmentsT []struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Urls         []string `json:"urls,omitempty"`
}

type BranchesT []struct {
	Branches BranchesT         `json:"branches,omitempty"`
	Category string            `json:"category"`
	Name     string            `json:"name"`
	Product  *FullProductNameT `json:"product,omitempty"`
}

type ExtensionsT []json.RawMessage

type FullProductNameT struct {
	Name                        string     `json:"name"`
	ProductId                   ProductIdT `json:"product_id"`
	ProductIdentificationHelper *struct {
		Cpe    string `json:"cpe,omitempty"`
		Hashes []*struct {
			FileHashes []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"file_hashes"`
			Filename string `json:"filename"`
		} `json:"hashes,omitempty"`
		ModelNumbers  []string `json:"model_numbers,omitempty"`
		Purls         []string `json:"purls,omitempty"`
		SbomUrls      []string `json:"sbom_urls,omitempty"`
		SerialNumbers []string `json:"serial_numbers,omitempty"`
		Skus          []string `json:"skus,omitempty"`
		XGenericUris  []*struct {
			Namespace string `json:"namespace"`
			Uri       string `json:"uri"`
		} `json:"x_generic_uris,omitempty"`
	} `json:"product_identification_helper,omitempty"`
	XExtensions ExtensionsT `json:"x_extensions,omitempty"`
}

type LangT string

type NotesT []struct {
	Audience   string         `json:"audience,omitempty"`
	Category   string         `json:"category"`
	GroupIds   ProductGroupsT `json:"group_ids,omitempty"`
	ProductIds ProductsT      `json:"product_ids,omitempty"`
	Text       string         `json:"text"`
	Title      string         `json:"title,omitempty"`
}

type ProductGroupIdT string

type ProductGroupsT []ProductGroupIdT

type ProductIdT string

type ProductsT []ProductIdT

type ReferencesT []struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary"`
	Url      string `json:"url"`
}

type SubpathT struct {
	Category             string     `json:"category"`
	NextProductReference ProductIdT `json:"next_product_reference"`
}

type VersionT string
