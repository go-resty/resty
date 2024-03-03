package examples

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func getTestDataPath() string {
	pwd, _ := os.Getwd()
	return filepath.Join(pwd, "../.testdata")
}


func assertType(t *testing.T, typ, v interface{}) {
	if reflect.DeepEqual(reflect.TypeOf(typ), reflect.TypeOf(v)) {
		t.Errorf("Expected type %t, got %t", typ, v)
	}
}

func assertError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error occurred [%v]", err)
	}
}

func assertErrorIs(t *testing.T, e, g error) (r bool) {
	if !errors.Is(g, e) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	}

	return true
}

func assertEqual(t *testing.T, e, g interface{}) (r bool) {
	if !equal(e, g) {
		t.Fatalf("Expected [%v], got [%v]", e, g)
	}

	return
}

func assertNotEqual(t *testing.T, e, g interface{}) (r bool) {
	if equal(e, g) {
		t.Errorf("Expected [%v], got [%v]", e, g)
	} else {
		r = true
	}

	return
}

func equal(expected, got interface{}) bool {
	return reflect.DeepEqual(expected, got)
}