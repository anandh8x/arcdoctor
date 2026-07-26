package doctor

import "testing"

func TestValidateAddressChecksumPresentation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		value      string
		want       string
		validation addressValidation
	}{
		{
			name:       "checksummed",
			value:      "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			want:       "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			validation: addressValid,
		},
		{
			name:       "lowercase is normalized",
			value:      "0xce084c9358fbc5200415012885c2f0f0906d400c",
			want:       "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			validation: addressValid,
		},
		{
			name:       "wrong mixed case",
			value:      "0xce084c9358FBC5200415012885c2F0F0906d400C",
			want:       "0xCe084c9358FBC5200415012885c2F0F0906d400C",
			validation: addressChecksumInvalid,
		},
		{
			name:       "malformed",
			value:      "0x1234",
			validation: addressMalformed,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, validation := validateAddress(test.value)
			if got != test.want || validation != test.validation {
				t.Errorf(
					"validateAddress() = %q, %d, want %q, %d",
					got,
					validation,
					test.want,
					test.validation,
				)
			}
		})
	}
}
