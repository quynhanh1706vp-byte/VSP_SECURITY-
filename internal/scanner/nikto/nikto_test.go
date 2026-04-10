package nikto

import (
	"context"
	"testing"

	"github.com/vsp/platform/internal/scanner"
)

func TestParse_Empty(t *testing.T) {
	input := []byte(`<?xml version="1.0" ?><niktoscan><scandetails></scandetails></niktoscan>`)
	findings, err := parseXML(input)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParse_SingleItem(t *testing.T) {
	input := []byte(`<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="192.168.1.1" targethostname="example.com">
    <item id="000001" osvdbid="0" osvdblink="" method="GET">
      <description>Server leaks inodes via ETags</description>
      <uri>/</uri>
      <namelink>http://example.com/</namelink>
      <iplink>http://192.168.1.1/</iplink>
    </item>
  </scandetails>
</niktoscan>`)

	findings, err := parseXML(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Tool != "nikto" {
		t.Errorf("Tool: got %q want nikto", f.Tool)
	}
}

func TestParse_MultipleItems(t *testing.T) {
	input := []byte(`<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="10.0.0.1" targethostname="test.local">
    <item id="000001" osvdbid="0" osvdblink="" method="GET">
      <description>Finding 1</description>
      <uri>/path1</uri>
      <namelink>http://test.local/path1</namelink>
      <iplink>http://10.0.0.1/path1</iplink>
    </item>
    <item id="000002" osvdbid="0" osvdblink="" method="POST">
      <description>Finding 2</description>
      <uri>/path2</uri>
      <namelink>http://test.local/path2</namelink>
      <iplink>http://10.0.0.1/path2</iplink>
    </item>
  </scandetails>
</niktoscan>`)

	findings, err := parseXML(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestParse_InvalidXML(t *testing.T) {
	_, err := parseXML([]byte(`not xml at all`))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestAdapter_Name(t *testing.T) {
	a := New()
	if a.Name() != "nikto" {
		t.Errorf("expected nikto, got %q", a.Name())
	}
}

func TestAdapter_RunNoURL(t *testing.T) {
	a := New()
	_, err := a.Run(context.TODO(), scanner.RunOpts{})
	if err == nil {
		t.Error("expected error when URL is empty")
	}
}
