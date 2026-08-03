package pki

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommandRunnerPassesArgumentsWithoutShellInterpretation(t *testing.T) {
	runner := CommandRunner{Executable: os.Args[0], Timeout: 2 * time.Second, Env: []string{"CERTARIUM_RUNNER_HELPER=1"}}
	output, err := runner.Run(context.Background(), "-test.run=TestRunnerHelper", "--", "$(touch /tmp/certarium-must-not-exist)", "a;b", "line\nvalue")
	if err != nil {
		t.Fatalf("run helper: %v", err)
	}
	for _, want := range []string{"$(touch /tmp/certarium-must-not-exist)", "a;b", "line\\nvalue"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("output %q missing literal %q", output, want)
		}
	}
	if _, err := os.Stat("/tmp/certarium-must-not-exist"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("shell metacharacters were interpreted")
	}
}

func TestCommandRunnerReturnsStableTimeoutError(t *testing.T) {
	runner := CommandRunner{Executable: os.Args[0], Timeout: 25 * time.Millisecond, Env: []string{"CERTARIUM_RUNNER_HELPER=1"}}
	_, err := runner.Run(context.Background(), "-test.run=TestRunnerHelper", "--", "sleep")
	if !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("error = %v, want ErrCommandTimeout", err)
	}
}

func TestRunnerHelper(t *testing.T) {
	if os.Getenv("CERTARIUM_RUNNER_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) == 1 && args[0] == "sleep" {
		time.Sleep(10 * time.Second)
		return
	}
	for _, arg := range args {
		println(strings.ReplaceAll(arg, "\n", "\\n"))
	}
	os.Exit(0)
}
