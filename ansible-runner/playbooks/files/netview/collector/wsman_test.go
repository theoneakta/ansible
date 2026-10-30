package main

import "testing"

// A WinRM Enumerate answer: one plain instance, one WQL projection (XmlFragment), an array, a nil, a datetime.
const enumAnswer = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Header/><s:Body><n:EnumerateResponse><n:EnumerationContext>uuid:1</n:EnumerationContext><w:Items>
<p:Win32_NetworkAdapterConfiguration xmlns:p="x"><p:Description>Intel</p:Description><p:IPAddress>192.168.3.15</p:IPAddress><p:IPAddress>fe80::1</p:IPAddress><p:MACAddress xsi:nil="true"/></p:Win32_NetworkAdapterConfiguration>
<w:XmlFragment><Caption>Microsoft Windows 11 Pro</Caption><LastBootUpTime><cim:Datetime xmlns:cim="y">2026-10-29T08:00:00Z</cim:Datetime></LastBootUpTime></w:XmlFragment>
</w:Items><w:EndOfSequence/></n:EnumerateResponse></s:Body></s:Envelope>`

func TestWsmanItems(t *testing.T) {
	root, err := parseXML([]byte(enumAnswer))
	if err != nil {
		t.Fatal(err)
	}
	resp := root.find("Body", "EnumerateResponse")
	if resp == nil || resp.find("EndOfSequence") == nil {
		t.Fatal("no EnumerateResponse / EndOfSequence")
	}
	items := resp.find("Items").kids
	if len(items) != 2 {
		t.Fatalf("%d items", len(items))
	}
	nic := items[0].props()
	if ips, ok := nic["IPAddress"].([]string); !ok || len(ips) != 2 || ips[1] != "fe80::1" {
		t.Errorf("IPAddress: %#v", nic["IPAddress"])
	}
	if _, ok := nic["MACAddress"]; ok {
		t.Error("a nil property kept")
	}
	// A projection: each item is an XmlFragment holding the properties.
	os := items[1].props()
	if os["Caption"] != "Microsoft Windows 11 Pro" || os["LastBootUpTime"] != "2026-10-29T08:00:00Z" {
		t.Errorf("projection: %#v", os)
	}
}

func TestPins(t *testing.T) {
	p := loadPins(t.TempDir())
	if p.check("ssh 10.0.0.5:22", "A") != nil || p.check("ssh 10.0.0.5:22", "A") != nil {
		t.Fatal("first and same key refused")
	}
	if p.check("ssh 10.0.0.5:22", "B") == nil {
		t.Fatal("another key accepted")
	}
	p.forget([]string{"ssh 10.0.0.5:22"})
	if p.check("ssh 10.0.0.5:22", "B") != nil {
		t.Fatal("the new key refused after forget")
	}
	if loadPins(p.path[:len(p.path)-len("/pins.json")]).pins["ssh 10.0.0.5:22"] != "B" {
		t.Fatal("not kept on disk")
	}
}
