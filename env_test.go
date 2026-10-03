package vbox

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Exercise os/exec's final environment, including duplicate-key handling.
func TestProcessEnvironment(t *testing.T) {
	if os.Getenv("VBOX_ENV_PROBE") == "1" {
		fmt.Printf("%s|%s|%s", os.Getenv("VBOX_TEST_SECRET"), os.Getenv("VBOX_TEST_VALUE"), os.Getenv("SKILLPROC_SOCKET"))
		os.Exit(0)
	}
	t.Setenv("VBOX_TEST_SECRET", "inherited")
	t.Setenv("VBOX_TEST_VALUE", "inherited")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		confined bool
		explicit []string
		want     string
	}{
		{"confined", true, nil, "|platform|socket"},
		{"unconfined", false, nil, "inherited|platform|socket"},
		{"explicit", true, []string{"VBOX_TEST_SECRET=provided", "VBOX_TEST_VALUE="}, "provided||socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, "-test.run=^TestProcessEnvironment$")
			cmd.Env = processEnv(cmd.Environ(), []string{"VBOX_ENV_PROBE=1", "VBOX_TEST_VALUE=platform", "SKILLPROC_SOCKET=socket"}, tc.explicit, tc.confined)
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != tc.want {
				t.Fatalf("environment=%q, err=%v; want %q", out, err, tc.want)
			}
		})
	}
}
