package gateway

import (
	"testing"
	"unicode/utf8"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ascii", "abc", "abc"},
		{"valid utf8 kept", "caf\xc3\xa9 " + nbspUTF8, "caf\xc3\xa9 " + nbspUTF8},
		{"latin1 copyright", "&copy " + copyLatin1 + " 2016", "&copy \xc2\xa9 2016"},
		{"latin1 nbsp", "a" + nbspLatin1 + "b", "a\xc2\xa0b"},
		{"cp1252 right quote", "device\x92s", "device\xe2\x80\x99s"},
		{"cp1252 euro and undefined", "\x80\x81", "\xe2\x82\xac\xc2\x81"},
		{"mixed valid and invalid", "\xc3\xa9" + copyLatin1, "\xc3\xa9\xc2\xa9"},
		{"replacement char kept", replChar, replChar},
		{"truncated sequence", "a\xe2\x82", "a\xc3\xa2\xe2\x80\x9a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decode([]byte(tt.in))
			if got != tt.want {
				t.Errorf("decode(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("decode(%q) is not valid UTF-8", tt.in)
			}
		})
	}
}

func TestNormSpace(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"\r\nUp\r\n                ", "Up"},
		{"a\n\tb", "a b"},
		{"Temperature" + nbspUTF8 + nbspUTF8 + "Currently 35", "Temperature Currently 35"},
		{"Temperature" + replChar + replChar + "Currently 35", "Temperature Currently 35"},
		{"x\xe2\x80\x8by", "x y"}, // zero-width space
		{"\xef\xbb\xbfBOM", "BOM"},
		{"1                 (Threshold -295)", "1 (Threshold -295)"},
		{"a\x85b", "a b"}, // invalid byte decodes as RuneError when ranging -> space
	}
	for _, tt := range tests {
		if got := normSpace(tt.in); got != tt.want {
			t.Errorf("normSpace(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormLabel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Secondary DNS Name" + nbspUTF8, "Secondary DNS Name"},
		{"\r\nPublic Subnet\r\n", "Public Subnet"},
		{"Status:", "Status"},
		{"Status : :", "Status"},
		{":", ""},
	}
	for _, tt := range tests {
		if got := normLabel(tt.in); got != tt.want {
			t.Errorf("normLabel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAlnumKey(t *testing.T) {
	for in, want := range map[string]string{
		"Tx Bias": "txbias", "TX-BIAS": "txbias", "TxBias": "txbias", "Rx  Power": "rxpower", "Vcc": "vcc",
	} {
		if got := alnumKey(in); got != want {
			t.Errorf("alnumKey(%q) = %q, want %q", in, got, want)
		}
	}
}
