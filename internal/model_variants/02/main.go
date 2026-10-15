package main

import "fmt"

type Publisher struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// Initialize exactly one detail pointer, even when its fields are empty
	// Or use a version field to indicate which version
	// Still reserves one pointer for each version, even if unused
	*Publisher20Details
	*Publisher21Details
}

type Publisher20Details struct {
	ContactDetails *string `json:"contact_details,omitempty"`
}

type Publisher21Details struct {
	Contact *Contact `json:"contact,omitempty"`
}

type Contact struct {
	Email *string `json:"email,omitempty"`
}

// ok reports version support
// Direct is possible and the methods are not needed, but if
// direct access, the caller has to ensure the version is correct
func (p *Publisher) GetContactDetails() (*string, bool) {
	if p.Publisher20Details == nil {
		return nil, false
	}
	return p.ContactDetails, true
}

func (p *Publisher) GetContact() (*Contact, bool) {
	if p.Publisher21Details == nil {
		return nil, false
	}
	return p.Contact, true
}

func main() {
	details, email := "Security team: security@example.com", "security@example.com"
	p20 := &Publisher{
		Name: "Vendor 20", Namespace: "https://example.com",
		Publisher20Details: &Publisher20Details{ContactDetails: &details},
	}
	p21 := &Publisher{
		Name: "Vendor 21", Namespace: "https://example.com",
		Publisher21Details: &Publisher21Details{Contact: &Contact{Email: &email}},
	}

	// Common field
	fmt.Println("2.0 name:", p20.Name)
	fmt.Println("2.1 name:", p21.Name)

	// Version-specific field access
	fmt.Println("2.0 contact_details:", *p20.ContactDetails)
	fmt.Println("2.1 contact.email:", *p21.Contact.Email)

	contact20, ok20 := p20.GetContactDetails()
	fmt.Println("2.0 GetContactDetails:", *contact20, "ok:", ok20)
	contact21, ok21 := p21.GetContact()
	fmt.Println("2.1 GetContact:", *contact21.Email, "ok:", ok21)

	wrong21, ok21 := p20.GetContact()
	fmt.Println("2.0 GetContact:", wrong21, "ok:", ok21)
	wrong20, ok20 := p21.GetContactDetails()
	fmt.Println("2.1 GetContactDetails:", wrong20, "ok:", ok20)

	// Panics:
	// p20.Contact
	// p21.ContactDetails
}

/*
	The calling API stays consistent (e.g. `GetContact()` always works/compiles),
	but the caller has to check the returned boolean to see if the version is correct.

	Stores the version either explicitly in a field or somewhat explicitly by not
	initializing the other version's details pointer.
*/
