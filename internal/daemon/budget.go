package daemon

import (
	"bufio"
	"fmt"
	"niflhel/internal/api"
	"os"
	"strconv"
	"strings"
)

func memoryBudget(reserved, available int64) error {
	if available < 256*api.MiB || reserved > available-256*api.MiB {
		return fmt.Errorf("insufficient available host memory for reserved VM envelopes (including 256 MiB host reserve)")
	}
	return nil
}
func availableMemory() (int64, error) {
	f, e := os.Open("/proc/meminfo")
	if e != nil {
		return 0, e
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		p := strings.Fields(scan.Text())
		if len(p) >= 2 && p[0] == "MemAvailable:" {
			n, e := strconv.ParseInt(p[1], 10, 64)
			return n * 1024, e
		}
	}
	return 0, fmt.Errorf("MemAvailable missing")
}
