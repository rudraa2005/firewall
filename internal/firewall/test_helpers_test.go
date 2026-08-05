package firewall

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
)

type handlerRoundTripper struct {
	handler http.Handler
}

func (h handlerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, r)
	result := recorder.Result()
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()

	return &http.Response{
		StatusCode:    result.StatusCode,
		Status:        result.Status,
		Header:        result.Header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}, nil
}
