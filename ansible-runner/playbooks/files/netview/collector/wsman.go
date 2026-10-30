package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

// WMI over WS-Management (WinRM): WQL queries enumerated by the WinRM service
// itself - no shell, no PowerShell process on the machine (an antivirus flags
// "powershell -EncodedCommand" over WinRM). NTLM over HTTPS: WinRM over plain
// HTTP insists on message encryption, which this doesn't do.
type wsman struct {
	url  string
	user string
	pass string
	http *http.Client
}

const (
	nsSoap = "http://www.w3.org/2003/05/soap-envelope"
	nsEnum = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	wql    = "http://schemas.microsoft.com/wbem/wsman/1/WQL"
)

func newWsman(url, user, pass string, tr *http.Transport) *wsman {
	return &wsman{url: url, user: user, pass: pass,
		http: &http.Client{Timeout: 90 * time.Second, Transport: ntlmssp.Negotiator{RoundTripper: tr}}}
}

func (w *wsman) envelope(action, namespace, body string) string {
	return `<s:Envelope xmlns:s="` + nsSoap + `" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:n="` + nsEnum + `"><s:Header>` +
		`<a:To>` + xmlText(w.url) + `</a:To>` +
		`<w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wmi/` + namespace + `/*</w:ResourceURI>` +
		`<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>` +
		`<a:Action s:mustUnderstand="true">` + nsEnum + `/` + action + `</a:Action>` +
		`<w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>` +
		`<a:MessageID>uuid:` + uuid() + `</a:MessageID>` +
		`<w:Locale xml:lang="en-US" s:mustUnderstand="false"/><w:OperationTimeout>PT60S</w:OperationTimeout>` +
		`</s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}

func (w *wsman) call(env string) (*xnode, error) {
	req, err := http.NewRequest("POST", w.url, strings.NewReader(env))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(w.user, w.pass) // what the NTLM negotiator signs in with
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	resp, err := w.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode == 401 {
		return nil, errors.New("WinRM refused the sign-in (HTTP 401)")
	}
	root, perr := parseXML(data)
	if resp.StatusCode != 200 {
		if perr == nil {
			if r := root.find("Body", "Fault", "Reason"); r != nil {
				return nil, fmt.Errorf("WinRM: %s", strings.TrimSpace(r.text()))
			}
		}
		return nil, fmt.Errorf("WinRM: HTTP %d", resp.StatusCode)
	}
	return root, perr
}

// query: the instances a WQL query returns, as {property: value or [values]}.
func (w *wsman) query(namespace, q string) ([]map[string]any, error) {
	root, err := w.call(w.envelope("Enumerate", namespace,
		`<n:Enumerate><w:OptimizeEnumeration/><w:MaxElements>500</w:MaxElements>`+
			`<w:Filter Dialect="`+wql+`">`+xmlText(q)+`</w:Filter></n:Enumerate>`))
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	resp := root.find("Body", "EnumerateResponse")
	for page := 0; resp != nil && page < 100; page++ {
		if items := resp.find("Items"); items != nil {
			for _, it := range items.kids {
				out = append(out, it.props())
			}
		}
		ctx := resp.find("EnumerationContext")
		if resp.find("EndOfSequence") != nil || ctx == nil {
			break
		}
		root, err = w.call(w.envelope("Pull", namespace,
			`<n:Pull><n:EnumerationContext>`+xmlText(ctx.text())+`</n:EnumerationContext><n:MaxElements>500</n:MaxElements></n:Pull>`))
		if err != nil {
			return out, err
		}
		resp = root.find("Body", "PullResponse")
	}
	return out, nil
}

// ------------------------------------------------------------------ a little XML tree
type xnode struct {
	name  string // local name
	attrs map[string]string
	kids  []*xnode
	chars string
}

func parseXML(b []byte) (*xnode, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	root := &xnode{}
	stack := []*xnode{root}
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		cur := stack[len(stack)-1]
		switch e := t.(type) {
		case xml.StartElement:
			n := &xnode{name: e.Name.Local, attrs: map[string]string{}}
			for _, a := range e.Attr {
				n.attrs[a.Name.Local] = a.Value
			}
			cur.kids = append(cur.kids, n)
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			cur.chars += string(e)
		}
	}
	if len(root.kids) == 0 {
		return nil, errors.New("not XML")
	}
	return root.kids[0], nil
}

// find: the first descendant along these names (each one a child of the last).
func (n *xnode) find(path ...string) *xnode {
	cur := n
	for _, p := range path {
		var next *xnode
		for _, k := range cur.kids {
			if k.name == p {
				next = k
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

func (n *xnode) text() string {
	s := n.chars
	for _, k := range n.kids {
		s += k.text()
	}
	return s
}

// props: an instance's properties - a repeated one (an array) as a list, a nil one left out.
func (n *xnode) props() map[string]any {
	m := map[string]any{}
	kids := n.kids
	if len(kids) == 1 && kids[0].name == "XmlFragment" { // a WQL projection's wrapper
		kids = kids[0].kids
	}
	for _, k := range kids {
		if k.attrs["nil"] == "true" {
			continue
		}
		v := strings.TrimSpace(k.text())
		switch old := m[k.name].(type) {
		case nil:
			m[k.name] = v
		case string:
			m[k.name] = []string{old, v}
		case []string:
			m[k.name] = append(old, v)
		}
	}
	return m
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func uuid() string {
	h := newID() + newID() + newID() // 36 hex digits
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}
