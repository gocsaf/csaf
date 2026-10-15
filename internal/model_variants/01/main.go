package main

import "fmt"

type Publisher interface {
	Name() string
	Namespace() string
}

type publisherBase struct {
	name      string
	namespace string
}

func (p *publisherBase) Name() string      { return p.name }
func (p *publisherBase) Namespace() string { return p.namespace }

type Publisher20 struct {
	publisherBase
	ContactDetails *string // CSAF 2.0 only.
}

type Publisher21 struct {
	publisherBase
	Contact *Contact // CSAF 2.1 only.
}

// Optional getters, depending on what kind of access is preferred
func (p *Publisher20) GetContactDetails() *string { return p.ContactDetails }
func (p *Publisher21) GetContact() *Contact       { return p.Contact }

type Contact struct {
	Email *string
}

func main() {
	details, email := "Security team: security@example.com", "security@example.com"
	var p20 Publisher = &Publisher20{
		publisherBase:  publisherBase{name: "Vendor 20", namespace: "https://example.com"},
		ContactDetails: &details,
	}

	// Does not need to specify the base struct:
	var p21 Publisher = &Publisher21{
		name: "Vendor 21", namespace: "https://example.com",
		Contact: &Contact{Email: &email},
	}

	// Common field
	fmt.Println("2.0 name:", p20.Name())
	fmt.Println("2.1 name:", p21.Name())

	// Version-specific field access
	if publisher, ok := p20.(*Publisher20); ok {
		fmt.Println("2.0 contact_details:", *publisher.ContactDetails)
		fmt.Println("2.0 GetContactDetails():", *publisher.GetContactDetails())
	}
	if publisher, ok := p21.(*Publisher21); ok {
		fmt.Println("2.1 contact.email:", *publisher.Contact.Email)
		fmt.Println("2.1 GetContact().Email:", *publisher.GetContact().Email)
	}

	// Wrong version: checked assertions return nil, false without panicking
	wrong21, ok21 := p20.(*Publisher21)
	fmt.Println("2.0 as *Publisher21:", wrong21, "ok:", ok21)
	wrong20, ok20 := p21.(*Publisher20)
	fmt.Println("2.1 as *Publisher20:", wrong20, "ok:", ok20)

	// Panics:
	// p20.(*Publisher21)
	// p21.(*Publisher20)

	// Does not compile:
	// p20.ContactDetails
	// p20.(*Publisher20).Contact
	// p20.GetContactDetails()
	// p20.(*Publisher20).GetContact()
	// p21.(*Publisher21).GetContactDetails()
}

/*
	Needs the caller to be aware of/check the version to request version specific fields
	The caller needs to cast (or use a helper functions like `toV20()` or `toV21()`) to access the version specific fields

	Stores the version implicitly in the type instead of explicitly in a field
*/
