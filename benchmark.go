package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
)

const count = 20

var devs = []string{"/dev/abuse0", "/dev/nbd0"}

func hdparm() error {
	file, err := os.Create("hdparm.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := io.MultiWriter(os.Stdout, file)
	//writer := file
	reg, err := regexp.Compile(`(\d+\.\d+) MB/sec`)
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		for _, d := range devs {
			buf, err := exec.Command("hdparm", "-t", "--direct", d).CombinedOutput()
			if err != nil {
				return err
			}
			if !reg.Match(buf) {
				return errors.New(string(buf))
			}
			mbs := reg.FindSubmatch(buf)[1]
			fmt.Fprintf(writer, "hdparm, %d, %s, %s\n", i, d, mbs)
		}
	}
	return nil
}

func ddWrite() error {
	file, err := os.Create("ddwrite.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := io.MultiWriter(os.Stdout, file)
	//writer := file
	reg, err := regexp.Compile(`(\d+\.\d+) s,`)
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		for _, d := range devs {
			buf, err := exec.Command(
				"dd", "bs=1M", "count=256",
				"if=/dev/zero", "of="+d, "conv=fdatasync").CombinedOutput()
			if err != nil {
				return err
			}
			if !reg.Match(buf) {
				return errors.New(string(buf))
			}
			sec, err := strconv.ParseFloat(string(reg.FindSubmatch(buf)[1]), 64)
			if err != nil {
				return err
			}
			fmt.Fprintf(writer, "ddwrite, %d, %s, %f\n", i, d, 268435456/sec/1024/1024)
		}
	}
	return nil
}

type WorkFunc func() error

func main() {
	err := hdparm()
	if err != nil {
		log.Fatal(err)
	}

	err = ddWrite()
	if err != nil {
		log.Fatal(err)
	}
}
