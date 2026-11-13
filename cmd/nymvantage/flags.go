package main

import "flag"

// parseInterspersed parses flags that may come before or after the
// positional arguments ("nymvantage tls example.com -n 5"). A lone "--" ends
// the flags.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		if args[0] == "--" {
			pos = append(pos, args[1:]...)
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	return fs.Parse(append([]string{"--"}, pos...))
}
