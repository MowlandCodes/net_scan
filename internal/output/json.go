package output

import (
	"encoding/json"
	"io"

	"github.com/MowlandCodes/net_scan/internal/scanner"
)

type jsonOutput struct {
	Total   int                  `json:"total"`
	Alive   int                  `json:"alive"`
	Dead    int                  `json:"dead"`
	Results []scanner.ScanResult `json:"results"`
}

func WriteJSON(w io.Writer, results []scanner.ScanResult) error {
	aliveCount := 0
	for _, r := range results {
		if r.Alive {
			aliveCount++
		}
	}

	out := jsonOutput{
		Total:   len(results),
		Alive:   aliveCount,
		Dead:    len(results) - aliveCount,
		Results: results,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
