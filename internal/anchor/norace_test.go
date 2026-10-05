//go:build !race

package anchor

// raceEnabled lets CPU-heavy property tests sample instead of exhausting under -race.
const raceEnabled = false
