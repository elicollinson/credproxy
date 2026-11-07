package main

// #include <termios.h>
import "C"

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// minSecret is the shortest secret key set accepts. Anything shorter is
// more likely a paste gone wrong than a real key, and too short to redact
// safely in responses.
const minSecret = 16

// readSecret reads one secret from f. From a terminal it prompts on stderr
// and reads a line with echo off; otherwise it reads everything, so a file
// can be piped in (key set gcp-sa < sa.json). The final newline is dropped.
func readSecret(f *os.File, prompt string) ([]byte, error) {
	var b []byte
	var err error
	if old, ok := termios(f); ok {
		b, err = readNoEcho(f, old, prompt)
	} else {
		b, err = io.ReadAll(io.LimitReader(f, 1<<20))
	}
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	if len(b) < minSecret {
		clear(b)
		return nil, fmt.Errorf("secret is shorter than %d bytes", minSecret)
	}
	return b, nil
}

func termios(f *os.File) (C.struct_termios, bool) {
	var t C.struct_termios
	return t, C.tcgetattr(C.int(f.Fd()), &t) == 0
}

func setTermios(f *os.File, t *C.struct_termios) error {
	if C.tcsetattr(C.int(f.Fd()), C.TCSANOW, t) != 0 {
		return errors.New("cannot set terminal mode")
	}
	return nil
}

// readNoEcho turns echo off for one line and always puts it back, on
// Ctrl-C too.
func readNoEcho(f *os.File, old C.struct_termios, prompt string) ([]byte, error) {
	noEcho := old
	noEcho.c_lflag &^= C.ECHO
	if err := setTermios(f, &noEcho); err != nil {
		return nil, err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sig)
		close(done)
		setTermios(f, &old)
		fmt.Fprintln(os.Stderr)
	}()
	go func() {
		select {
		case <-sig:
			setTermios(f, &old)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	fmt.Fprint(os.Stderr, prompt)
	// A terminal line holds at most 1024 bytes (MAX_CANON); longer secrets,
	// such as an SA JSON, have to be piped in.
	line, err := bufio.NewReader(f).ReadSlice('\n')
	if errors.Is(err, io.EOF) && len(line) > 0 {
		err = nil
	}
	return bytes.Clone(line), err
}
