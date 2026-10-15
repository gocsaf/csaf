package main

import "fmt"

type Publisher struct {
	Name      string
	Namespace string
	details   publisherDetails
}

type publisherDetails interface {
	version() string // optional
}

// optional
type version20 struct{}
type version21 struct{}

func (version20) version() string { return "2.0" }
func (version21) version() string { return "2.1" }

type publisher20Details struct {
	version20
	ContactDetails *string
}

type publisher21Details struct {
	version21
	Contact *Contact
}

type Contact struct {
	Email *string
}

// ok reports version support
func (p *Publisher) GetContactDetails() (*string, bool) {
	details, ok := p.details.(*publisher20Details)
	if !ok || details == nil {
		return nil, false
	}
	return details.ContactDetails, true
}

func (p *Publisher) GetContact() (*Contact, bool) {
	details, ok := p.details.(*publisher21Details)
	if !ok || details == nil {
		return nil, false
	}
	return details.Contact, true
}

func main() {
	details, email := "Security team: security@example.com", "security@example.com"
	p20 := &Publisher{
		Name: "Vendor 20", Namespace: "https://example.com",
		details: &publisher20Details{ContactDetails: &details},
	}
	p21 := &Publisher{
		Name: "Vendor 21", Namespace: "https://example.com",
		details: &publisher21Details{Contact: &Contact{Email: &email}},
	}

	// Common field
	fmt.Println("2.0 name:", p20.Name)
	fmt.Println("2.1 name:", p21.Name)

	fmt.Println("Versions from embedded markers:", p20.details.version(), p21.details.version())

	// Version-specific field access
	contact20, ok20 := p20.GetContactDetails()
	fmt.Println("2.0 GetContactDetails:", *contact20, "ok:", ok20)
	contact21, ok21 := p21.GetContact()
	fmt.Println("2.1 GetContact:", *contact21.Email, "ok:", ok21)

	// Wrong version: checked methods return nil, false
	wrong21, ok21 := p20.GetContact()
	fmt.Println("2.0 GetContact:", wrong21, "ok:", ok21)
	wrong20, ok20 := p21.GetContactDetails()
	fmt.Println("2.1 GetContactDetails:", wrong20, "ok:", ok20)

	// Empty details still identify the supported version with nil, true
	p21.details = &publisher21Details{}
	absent, supported := p21.GetContact()
	fmt.Println("2.1 absent optional contact:", absent, "ok:", supported)

	// Does not compile:
	// p20.Contact
	// p21.ContactDetails
}
