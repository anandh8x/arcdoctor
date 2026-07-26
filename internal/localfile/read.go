package localfile

import (
	"fmt"
	"io"
	"os"
)

func Read(path string, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("maximum file size must not be negative")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}
