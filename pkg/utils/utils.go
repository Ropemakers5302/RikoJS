package utils

import (
	"fmt"
	"os"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
)

func PrintInfo(msg string) {
	fmt.Printf("%s[INFO]%s %s\n", ColorGreen, ColorReset, msg)
}

func PrintWarn(msg string) {
	fmt.Printf("%s[WARN]%s %s\n", ColorYellow, ColorReset, msg)
}

func PrintVuln(msg string) {
	fmt.Printf("%s[VULN]%s %s\n", ColorRed, ColorReset, msg)
}

func PrintError(msg string) {
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg)
}

func PrintDebug(msg string) {
	fmt.Printf("%s[DEBUG]%s %s\n", ColorPurple, ColorReset, msg)
}

func PrintData(msg string) {
	fmt.Printf("%s[DATA]%s %s\n", ColorCyan, ColorReset, msg)
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
