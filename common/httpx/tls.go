package httpx

import (
	"crypto/x509"
	"net/http"
)

type TlsData struct {
	DNSNames         []string `json:"dns_names,omitempty"`
	Emails           []string `json:"emails,omitempty"`
	CommonName       []string `json:"common_name,omitempty"`
	Organization     []string `json:"organization,omitempty"`
	IssuerCommonName []string `json:"issuer_common_name,omitempty"`
	IssuerOrg        []string `json:"issuer_organization,omitempty"`
	SubjectOrg       []string `json:"subject_org,omitempty"`
	SubjectOrgUnit   []string `json:"subject_org_unit,omitempty"`
	ValidCert        bool     `json:"cert_valid"`
}

func (h *HTTPX) TlsGrab(r *http.Response) *TlsData {
	if r.TLS != nil {
		var tlsdata TlsData
		certs := x509.NewCertPool()
		for _, certificate := range r.TLS.PeerCertificates {
			certs.AddCert(certificate)
			tlsdata.DNSNames = append(tlsdata.DNSNames, certificate.DNSNames...)
			tlsdata.Emails = append(tlsdata.Emails, certificate.EmailAddresses...)
			tlsdata.CommonName = append(tlsdata.CommonName, certificate.Subject.CommonName)
			tlsdata.Organization = append(tlsdata.Organization, certificate.Subject.Organization...)
			tlsdata.IssuerOrg = append(tlsdata.IssuerOrg, certificate.Issuer.Organization...)
			tlsdata.IssuerCommonName = append(tlsdata.IssuerCommonName, certificate.Issuer.CommonName)
		}
		tlsdata.SubjectOrg = r.TLS.PeerCertificates[0].Subject.Organization
		tlsdata.SubjectOrgUnit = r.TLS.PeerCertificates[0].Subject.OrganizationalUnit
		//root_certs, err = x509.SystemCertPool()
		//peer_cert_chain := [][]*x509.Certificate{r.TLS.PeerCertificates}
		tlsdata.ValidCert = true
		verOpts := x509.VerifyOptions{Intermediates: certs}
		if _, err := r.TLS.PeerCertificates[0].Verify(verOpts); err != nil {
			tlsdata.ValidCert = false
		}
		return &tlsdata
	}
	return nil
}
