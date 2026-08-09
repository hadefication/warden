package mcpserver

// version is reported to MCP clients during initialisation. It is overridden at
// build time by install.sh via -ldflags.
var version = "dev"
