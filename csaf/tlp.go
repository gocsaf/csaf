package csaf

const (
	// TLPLabelClear is the 'CLEAR' policy (CSAF v2.1 & TLP v2 only).
	TLPLabelClear = "CLEAR"
	// TLPLabelAmberStrict is the 'AMBER+STRICT' policy (CSAF v2.1 & TLP v2 only).
	TLPLabelAmberStrict = "AMBER+STRICT"
)

// TLPLabelDefault returns the label of distributions based on CSAF version.
func TLPLabelDefault(version SpecVersion) TLPLabel {
	if version == Version21 {
		return TLPLabelClear
	}
	return TLPLabelWhite
}
