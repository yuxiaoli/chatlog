package windowsv3

import (
	"reflect"
	"testing"
)

func TestContactLabelIDsForKeyIncludesRawAndResolvedIDs(t *testing.T) {
	labelNames := map[string]string{
		"5": "Family",
		"3": "Family",
		"7": "Work",
	}

	got := contactLabelIDsForKey("Family", labelNames)
	want := []string{"3", "5", "Family"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("contactLabelIDsForKey() = %#v, want %#v", got, want)
	}
}

func TestContactLabelIDsForKeySkipsEmptyAndDuplicateIDs(t *testing.T) {
	got := contactLabelIDsForKey(" 3 ", map[string]string{
		"3":   " 3 ",
		" 3 ": " 3 ",
		"":    " 3 ",
	})
	want := []string{"3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("contactLabelIDsForKey() = %#v, want %#v", got, want)
	}
}
