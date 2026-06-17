package config

import (
	"fmt"
)

var (
	Version = "v1.3.0"
	Logo    = `

██████╗ ███╗   ██╗███████╗███████╗██╗     ██╗   ██╗██╗  ██╗
██╔══██╗████╗  ██║██╔════╝██╔════╝██║     ██║   ██║╚██╗██╔╝
██║  ██║██╔██╗ ██║███████╗█████╗  ██║     ██║   ██║ ╚███╔╝ 
██║  ██║██║╚██╗██║╚════██║██╔══╝  ██║     ██║   ██║ ██╔██╗ 
██████╔╝██║ ╚████║███████║██║     ███████╗╚██████╔╝██╔╝ ██╗
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                Version: %s
												
`
)

// PrintLogo prints the program logo and version information
func PrintLogo() string {
	return fmt.Sprintf(Logo, Version)
}
