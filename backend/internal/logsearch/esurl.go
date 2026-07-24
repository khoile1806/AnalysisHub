package logsearch

// BaseURL returns the Elasticsearch endpoint this client writes to. Callers that
// have to issue a query the client does not wrap (the Sigma offline scan builds
// its own _search DSL) need the exact endpoint the ingest path indexed into.
func (c *ESClient) BaseURL() string {
	return c.baseURL
}
