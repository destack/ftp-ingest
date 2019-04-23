package cmd

import (
	"eljefedelrodeodeljefe/ftp-ingest/pkg/server"

	"github.com/spf13/cobra"
)

// byeCmd represents the bye command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		server.StartFTPServer()
	},
}

func init() {
	RootCmd.AddCommand(startCmd)
}
